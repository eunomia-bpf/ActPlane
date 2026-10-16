---
name: paper-logic
description: Review a LaTeX paper for argument-level logic, cross-section consistency, and house style. Complements /paper-review (sentence-level style) with whole-paper reasoning checks.
when_to_use: Check paper logic, argument structure, cross-section consistency, number reconciliation, terminology drift, review whole paper before submission
argument-hint: [paper-dir-or-section-files]
allowed-tools: Read Bash(grep *) Bash(wc *) Bash(ls *) Bash(find *)
---

# Academic Writing: Logic & Consistency Review

Review the paper at `$ARGUMENTS` (a directory of sections or specific files)
for argument-level logic and cross-section consistency. If no argument is
given, locate the paper sources (e.g., `sections/*.tex` plus the main file
containing the abstract) and confirm the file set with the user.

This skill checks the **whole-paper layer**: does the argument hold together,
do the numbers reconcile, is the terminology stable. For sentence-level prose
(nominalizations, weak openings, word choice), run `/paper-review` per
section, which both reviews and applies its fixes. Do not duplicate its
sentence-level findings. The one exception is section M's mechanical greps
(punctuation, agreement), which enforce house style at whole-paper scope
because they catch drift that per-section review misses.

All examples below are from a **fictional paper** about a fictional adaptive
caching system. They illustrate the *shape* of each antipattern; never copy
them into your report. Every finding must quote the actual paper under review.

## Output contract (non-negotiable)

Your report is incomplete unless ALL of the following hold. Re-walk the
checklists until they do.

1. **Every checklist ID (A1–A7, B1–B5, C1–C7, M, P) appears in the report**,
   either with findings or with the line `[Xn] checked — no findings`, plus
   one sentence saying what you looked at. Silent skips are not allowed.
2. **Every finding has all four parts**: `file:line`, a verbatim quote from
   the paper under review, a problem statement that names the *reasoning*
   error (not "this is unclear"), and a concrete fix — for prose problems, a
   full rewritten sentence, not "consider rephrasing".
3. **The three working tables are filled in and printed** (term, number,
   promise), built from the paper under review. Do not write any finding
   before the tables are complete: most logic findings fall out of the
   tables, and skipping them is how reviews end up shallow.
4. **The mechanical greps in section M were actually run** and each hit
   triaged (finding / false positive, one line each).
5. **Calibration**: a mature 5-section systems paper typically yields
   **15–30 findings** across severities. If you have fewer than 10, you have
   under-checked — re-walk A and B with the tables in front of you. If you
   have zero Must-fix findings, explicitly state which Must-fix categories
   you verified and how.
6. Findings are sorted Must fix → Should fix → Consider, and the report ends
   with the three tables, the top-5 list, and the verdict paragraph.

## Severity rubric

- **Must fix**: a reviewer can reject on it — circular argument, numbers that
  contradict each other, claim without support, garbled contribution item,
  undefined term a reader cannot decode.
- **Should fix**: weakens credibility but doesn't break the argument —
  terminology drift, late definitions, false precision, renumbering debris.
- **Consider**: judgment calls — paragraph splits, citation placement,
  hedging *word choice* when scope is preserved. A dropped scope qualifier
  or a body-hedged claim turned absolute is A4/A5 (Must or Should), never
  Consider.

## Process

1. Read **all** section files in order, plus any terminology-conventions file
   the project keeps (e.g., `wording.md`) if present. Logic problems are
   invisible in a single section — never run this skill on one file alone.
2. **First pass (build, don't judge)**: fill the three working tables below.
3. Run the mechanical greps (section M); triage every hit.
4. **Second pass (judge)**: walk checklists A–C against the tables.
5. Walk the per-section protocol (section P).
6. Write the report per the output contract.

## The three working tables

Formats below, illustrated with fictional rows. Build them from the actual
paper.

### Term table
One row per recurring concept. The "names used" column exposes drift.

| Concept | Canonical term (per conventions file, if any) | Names actually used (with locations) | First defined at |
|---|---|---|---|
| a unit of admission logic | predicate | predicate (02:§2.2), filter (05:RQ1), policy (05:RQ2) | 02:§2.2 |

A concept with 2+ names, or one name covering 2+ concepts, is a C1 finding.
A "first defined at" that comes *after* a use is a C2 finding.

### Number table
One row per quantitative claim. Same fact in multiple places = one row with
multiple locations; mismatched forms are B1 findings, reader-derivable-only
values are B2 findings.

| Fact | Value & form at each location | Locations | Source |
|---|---|---|---|
| hit-rate advantage | "1.8–2.4×" / "15–22 pp" / raw 61 vs 25–34 | intro:¶5, eval:§6.2 text, Tab.2 | only derivable from Tab.2 by reader arithmetic → B2 |

### Promise table
One row per claim in the abstract, intro, or contributions list.

| Promise (quoted, with qualifiers) | Where supported | Qualifier preserved? |
|---|---|---|
| "improves tail latency on production workloads" | §6.4 (12 of 80 workloads, selected for cache sensitivity) | NO — eval scopes to subset, intro doesn't → A4 |

## A. Argument-structure antipatterns

### A1. Solution vocabulary in the motivation
Motivation/empirical/background sections must describe the problem in
problem-domain terms. If they classify the world using the system's own
mechanisms, the study stops being independent evidence and begs the question.

**Bad** (in a workload-study section):
> These access patterns map directly to our epoch-counters and
> ghost-list primitives.

**Good** (same section):
> Three recurring patterns emerge: bursty re-reference, scan pollution, and
> slow drift. All three require admission decisions that depend on history
> beyond the current request.

…and in Design: "The three patterns identified in §2 reduce to two
mechanisms: epoch counters and ghost lists."

**How to check**: list the design section's mechanism nouns, then grep for
each in every section that precedes the design. Each hit in
motivation/background is a finding unless it is citing prior work.

### A2. Self-referential categories used as neutral populations
Defining a category by reference to the system, then reporting its size as an
independent finding, is circular.

**Bad**:
> …the subset of requests that \sys{} can intercept is \emph{trackable}. […]
> Our study finds that 73% of requests are trackable.

**Good**:
> A request is \emph{trackable} if it carries an object identifier visible at
> the proxy layer, independent of any particular system. The study finds 73%
> of requests are trackable, and \sys{} targets exactly this class.

**How to check**: for every `\emph{}`d or defined category, ask "does the
definition mention the system?" If yes, every later use of that category's
count as a population is a finding.

### A3. Broken requirement→challenge→component chains
If the motivation derives N requirements, the design must visibly consume all
N. Count both ends and demand an explicit mapping.

**Bad**: the motivation summary lists four requirements (history-aware
admission, low memory, isolation, observability); the design opens "Two key
challenges arise" and resolves them with "three techniques"; isolation and
observability map to neither.

**Good**: a mapping sentence at the start of design: "Requirements R1–R2
raise challenge C1, addressed by epoch counters (§4.1) and ghost lists
(§4.2); R3 raises C2, addressed by per-tenant partitions (§4.3); R4 is an
implementation property, evaluated in §6.3."

**How to check**: write out three literal lists (requirements, challenges,
components) with locations; draw the mapping; report every orphan on either
side as a finding.

### A4. Conclusion outruns the evidence
Claims scoped to a selected subset must stay scoped in every restatement, and
hedging level for the same claim must be identical everywhere.

**Bad**: eval says "These results **suggest** that history-aware admission
improves tail latency **on the 12 cache-sensitive workloads**"; conclusion
says "\sys{} **improves** tail latency on production workloads."

**Good**: the conclusion repeats both the hedge and the scope, or the eval
explicitly justifies upgrading the claim.

**How to check**: for each promise-table row, diff the qualifiers ("suggest",
"on the subset", "up to", "in our setting") between the eval sentence and
every restatement in abstract, intro, and conclusion. Any dropped qualifier
is a finding.

### A5. Absolute claims for non-absolute limitations
Reserve "cannot", "never", "impossible", and "guarantees" for structural,
by-construction facts (a stateless mechanism cannot track cross-event state;
tool-call interception cannot observe effects outside the tool boundary).
Limitations that are a matter of cost or effort ("an administrator could,
with enough work") take "hard", "impractical", or "rarely". Also check the
reverse drift: a claim hedged in the body must not strengthen to an absolute
in the abstract or intro.

### A6. A leap presented as an observation
"X has property P; this makes X the natural Y" is an argument, not a fact.
Either rebut the obvious objection in place or forward-reference where it is
handled.

**Bad**:
> Application developers already know their access patterns. This makes them
> the natural authors of admission policy.

**Good**:
> Application developers already know their access patterns, so they hold the
> context that admission policy needs. Letting tenants author policy raises
> an isolation problem, which we address by bounding each tenant's policy to
> its own partition (§4.3).

**How to check**: grep for `natural|clearly|obviously|therefore|this makes|
this means` in intro/motivation; for each hit, ask "what objection would a
hostile reviewer raise here, and is it answered or forward-referenced?"

### A7. Two arguments packed into one paragraph
One paragraph, one claim. **How to check**: for each intro/motivation
paragraph, write its one-line claim; if the line needs "and also", split the
paragraph and report it, naming both claims.

## B. Quantitative-consistency antipatterns

### B1. Numbers that don't reconcile across sections
Every number in abstract/intro/conclusion must appear verbatim in (or be
trivially derivable from a single labeled place in) the evaluation, and the
same result must keep one canonical form.

**Bad**: intro "1.8–2.4×"; eval text "15–22 percentage points" and "2×";
table raw counts — three forms, no anchor sentence connecting them.

**Good**: one headline form, printed next to its table, reused verbatim:
"serves 61 of 90 bursty workloads from cache, 1.8–2.4× the 25–34 of the
baselines (Table 2)".

### B2. Forced reader arithmetic
If the headline claim is a ratio or delta, print it beside the table it comes
from. **How to check**: for each abstract/intro number, search the eval for
it verbatim; if you had to compute it from table cells, so will the reviewer
— that is the finding, and the fix is an anchor sentence.

### B3. Denominator hygiene
Every rate names numerator and denominator at first use; exclusions are
stated *before* the rate; subset selection states the rule, counts the
remainder, and scopes conclusions (cross-check A4).

**Bad**: "\sys{} eliminates 70% of avoidable misses. […two paragraphs
later…] Cold-start runs are excluded from the miss-rate denominator."

**Good**: "Of 120 avoidable misses, \sys{} eliminates 84 (70%). The 40
cold-start runs are excluded up front because no admission policy can serve
a first access."

**How to check**: grep for `%` and `rate`; for each, write `value = N/D` with
both numbers named in the same paragraph. Missing N or D, or a post-hoc
exclusion, is a finding.

### B4. False precision and unsourced constants
Significant digits must match measurement reliability; constants from outside
the experiment need citations.

**Bad**: "\$0.0314 per query […] At typical cloud egress rates, about
\$12.47 per workload." (four significant digits against an uncited price
assumption)

**Good**: "about \$0.03 per query, versus roughly \$12 per workload at
list-price cloud egress~\cite{cloudpricing2026}".

**How to check**: grep for `\$[0-9]`, `orders of magnitude`, and 3+
significant-digit values; each needs a source (measurement, citation, or
shown derivation).

### B5. Metrics doing hidden work
If the metric definition makes an outcome count favorably for one system and
unfavorably for another *by construction*, disclose it in the sentence that
makes the comparison, not paragraphs later.

**Bad**: praising an ablation's zero wrongful evictions in one paragraph, and
only later noting that the metric counts an object re-fetched within the same
epoch as "retained" for the ablation but "evicted" for the full system.

**Good**: "the ablation's zero wrongful evictions partly reflects the metric:
without prefetch, re-fetches land in the same epoch and score as retained,
while the same objects score as evicted under full \sys{}."

**How to check**: for every cross-system comparison, re-read the metric
definition and ask "could two systems with identical behavior score
differently because of how outcomes are labeled?" If yes, the disclosure must
be co-located with the comparison.

## C. Consistency and bookkeeping antipatterns

### C1. Terminology drift
One concept, one term, throughout — enforce the project's terminology
conventions file where present. Flag (a) near-synonym alternation for one
referent, (b) one word for two concepts. The term table makes both visible;
report each drifting concept as one finding listing all locations.

### C2. Defined-before-used
Every acronym, notation, configuration name, and dataset label is defined
before first use — **including figure captions and table headers**, which
readers hit out of order.

**Bad**: a figure caption says "CG-32 and CG-128"; the CG-$N$ notation is
defined two subsections later; "warm-path configurations" is used in one
setup paragraph and explained at the end of a different subsection.

**How to check**: for each notation in the term table, compare
first-definition location against first-use location, treating each figure
caption as used at its `\begin{figure}` line.

### C3. Renumbering debris
After RQs/sections/figures are renumbered, stale labels and filenames remain.

**Bad**: figures named `rq1_*.pdf` are all cited inside the RQ2 subsection,
`rq2_*.pdf` inside RQ3, and so on — every figure filename is off by one
against the prose that cites it.

**How to check**: grep `includegraphics` and `\label{`, and compare each
filename/label against the number of the subsection citing it. Also check
that anything *named* in the intro (a benchmark, a dataset, a metric) is
introduced by the same name in its own section.

### C4. Who-does-what reconstructability
Setups with multiple models/agents/judges/generators state every role once,
in one place, before results — who generates the workload, who runs it, who
translates configurations, who judges outcomes, and what software or model
backs each role.

**Good** (one place):
> Roles: generator G (model A) produces the traces, translator T (model B)
> writes the configurations, model C is the system under test (replicated
> with model D), and the outcome judge runs on the same model as the system
> under test.

**How to check**: build the roles table yourself from the eval text. Count
how many paragraphs you needed. More than one place = finding; a role you
cannot resolve at all = Must fix.

### C5. Parallelism and completeness in enumerations
Contribution lists, RQ lists, and itemized claims are grammatically parallel,
and each item is a complete sentence. A garbled contribution item is a Must
fix: it is the most-read sentence after the abstract.

**Bad**: "An evaluation on our admission benchmark building on the workload
study, external latency and cost benchmarks covering batch and interactive
workloads." (no main verb; not parallel)

**How to check**: read each list item aloud as a standalone sentence; check
all items share the same grammatical skeleton ("An X that Y").

### C6. Agentless claims
Every verification step names the actor and the criterion.

**Bad**: "We manually corrected samples flagged as requiring double-checking"
(flagged by whom, against what rule?); "all of which matched expectations"
(whose expectations?).

**Good**: "the judge flags low-confidence verdicts, and two authors re-label
all flagged samples against the written rubric".

**How to check**: grep `flagged|validated|verified|reviewed|matched|confirmed`
in methodology text; each hit needs a named actor and criterion.

### C7. Figure–prose agreement
Numbers repeated in captions must match the prose exactly (count, rounding,
units), and each caption must state the takeaway, not just the axes.
**How to check**: for every number inside a `\caption{}`, find its twin in
the body text; flag mismatches and takeaway-free captions.

## M. Mechanical greps (run all; triage every hit)

Adjust paths to the actual file set.

```bash
# ~ used as "approximately" (renders as non-breaking space; the "about" vanishes)
grep -n '[ (]~[0-9]' *.tex sections/*.tex

# em-dashes in prose, LaTeX and Unicode forms (house style; table --- for N/A is OK)
grep -n -- '---\|—' sections/*.tex | grep -v '& *--- *&\|--- *\\\\'

# subject-verb agreement: "does" followed by a plural subject
grep -nE 'does [^.?]*\b\w+(ies|s)\b.*\b(improve|prevent|reduce|achieve)' sections/*.tex

# e.g./i.e. punctuation consistency (counts should not both be nonzero)
grep -c 'e\.g\.,' sections/*.tex; grep -c 'e\.g\.[^,]' sections/*.tex

# stale figure numbering and labels (compare against citing subsection)
grep -n 'includegraphics\|\\label{fig:\|\\ref{fig:' sections/*.tex

# semicolons joining clauses (house style; lists OK) — triage each
grep -n '; [a-z]' sections/*.tex

# rates and percentages for the B3 denominator audit
grep -n '[0-9]%\|percent\|rate' sections/*.tex

# unsourced money / magnitude claims for B4
grep -n '\\\$[0-9]\|orders of magnitude' sections/*.tex
```

Also check by reading (no grep possible):
- Citations interrupting the subject–verb path: move cite blocks to the end
  of the clause when they separate subject from verb by more than ~7 words.
- Anonymity: repo URLs, author-identifying system names, acknowledgment
  remnants — flag if the venue is double-blind.

## House style (always enforce)

- **No em-dashes (`---`)** in paper text. Use commas, parentheses, or
  restructure. Table cells using `---` for "not applicable" are OK.
- **Avoid semicolons** joining independent clauses. Use periods, conjunctions
  (", and", ", but"), or causal connectors ("because", "so", "since").
  Semicolons are OK inside parenthetical lists.
- **Academic prose, not notes.** Causal connectors and flowing sentences, not
  strings of short declaratives. Concrete examples before abstract
  definitions. Every design decision states its "why" before its "what".

## P. Per-section protocol

**Abstract / Intro**: every number traced to the eval (B1/B2); every claim in
the promise table with qualifiers (A4); one paragraph = one claim (A6);
"we argue/we observe" steps checked for leaps (A5); contribution list checked
for parallelism (C5) and 1:1 mapping to sections.

**Background / Motivation / Empirical or workload study**: no solution
vocabulary (A1); categories defined system-independently (A2); the closing
summary's requirements recorded for A3; counts here are the canonical source
for every later population claim — record them in the number table.

**Design**: opening consumes all requirements (A3); each mechanism's "why"
traces to a motivation finding by explicit reference; terms introduced here
checked against the conventions file (C1/C2).

**Implementation**: numbers (LoC, limits) recorded in the number table;
"future work" admissions cross-checked against any capability claimed
earlier (A4).

**Evaluation**: roles stated once (C4); every rate's denominator audited
(B3); metric-construction biases disclosed at the comparison (B5); subset
selections scoped (A4); figure filenames vs section numbers (C3); captions
vs prose (C7); notation defined before the first figure that uses it (C2).

**Related work**: each contrast sentence states a checkable difference, not
adjectives; no claims about your own system that the eval did not support.

**Conclusion**: pure restatement — any number or scope not identical to the
eval's form is a finding (A4/B1).

## Calibration example (expected depth per finding)

Fictional findings, at the depth every real finding must match:

```
[A2][Must] sections/02-motivation.tex:217 "the subset of requests that
\sys{} can intercept is \emph{trackable}"
  Problem: the category is defined by what the system can do, then §6.1
  ("our study finds 73% of requests are trackable") uses its size as a
  neutral population — the denominator of the coverage claim is circular.
  Fix: "A request is trackable if it carries an object identifier visible at
  the proxy layer, independent of mechanism." State the \sys{} alignment
  once, separately.

[B3][Must] sections/05-evaluation.tex:514+520 "eliminates 70% of avoidable
misses" … "cold-start runs are excluded from the miss-rate denominator"
  Problem: the exclusion that shapes the headline rate is disclosed two
  paragraphs after the rate; a reviewer reading linearly recomputes the rate
  with different assumptions.
  Fix: fold numerator, denominator, and exclusion into the first statement:
  "Of 120 avoidable misses, \sys{} eliminates 84 (70%). The 40 cold-start
  runs are excluded up front because no admission policy can serve a first
  access."

[C3][Should] sections/05-evaluation.tex:91,207,244 figures rq1_pipeline.pdf,
rq1_hitrate.pdf, rq1_breakdown.pdf all cited inside §RQ2
  Problem: figure filenames carry a stale RQ numbering (every eval figure is
  off by one), signaling unmaintained renumbering to reviewers.
  Fix: rename the files to match the current RQ numbers and update the
  \includegraphics paths.
```

## Output format

1. **Coverage checklist** first: one line per ID (A1–A7, B1–B5, C1–C7, M,
   P), each `findings: N` or `checked — no findings (looked at: …)`.
2. **Findings**, grouped by ID, sorted Must fix → Should fix → Consider, each
   in the four-part format above.
3. **The three working tables** (term, number, promise), filled in from the
   paper under review.
4. **Top 5 highest-leverage fixes.**
5. **Verdict paragraph**: does the chain motivation → requirements → design →
   evaluation → conclusion close, and where are the weakest links?
