# What Do Developers Tell Their Agents? A Statement-Level Analysis of Agent Instruction Files

## Abstract

AI coding agents are increasingly governed by natural-language instruction
files (CLAUDE.md, AGENTS.md). Prior empirical
studies classify these files by topic (Architecture, Testing, Security) at
file or section granularity, but do not distinguish descriptions from
directives, do not extract individual rules, and do not assess
enforceability. This paper presents the first statement-level analysis of
agent instruction files. We extract individual statements from instruction
files in N popular open-source projects, classify each statement along two
axes (description vs. directive; directive subtype), and assess the
enforceability of each directive using the intent/action/behavior
framework: can the directive be enforced at the intent level (the agent's
own compliance), the action level (tool-call interception), or the
behavior level (OS-level observation of system calls and their
provenance)? We find that
(TODO: headline findings). Our taxonomy and annotated dataset provide a
foundation for future work on agent compliance measurement and
enforcement system design.

---

## 1. Introduction

AI coding agents such as Claude Code, OpenAI Codex CLI, and GitHub Copilot
Workspace operate as autonomous processes with access to shells, file
systems, package managers, and network services. To guide agent behavior,
project maintainers write natural-language instruction files that are
injected into the agent's context at the start of each session. These files
have rapidly become a standard practice: Chatlatanagulchai et al. report
that 59--67% of instruction files are modified in multiple commits, with
median update intervals of 1--3 days.

Five prior empirical studies have characterized these files along dimensions
of content taxonomy, structural properties, maintenance practices, and
efficiency impact (see Section 7). However, all prior studies classify at
file level or section-heading level, asking "what topics does this file
cover?" None extracts individual rules, distinguishes descriptions from
directives, or assesses whether individual rules are machine-enforceable.

This gap matters because the emerging field of agent harness
engineering---the practice of building infrastructure to make agents
reliable---requires knowing not just what topics developers address but
what specific rules they write, how those rules distribute across projects,
and which rules can be enforced by deterministic mechanisms at different
layers of the system stack.

This paper addresses this gap with a statement-level analysis of agent
instruction files. We make three contributions:

1. A **statement-level taxonomy** that classifies individual statements
   extracted from instruction files along two axes: content type
   (description vs. directive) and directive subtype (style, build,
   constraint, communication).

2. A **statement-level corpus** of N statements extracted from instruction
   files in M projects, annotated along the taxonomy and released as a
   public dataset.

3. An **enforceability analysis** using the intent/action/behavior
   framework that assesses each directive at three levels (intent, action,
   behavior), identifying the subset that requires cross-object state
   tracking at the behavior level and cannot be enforced at the action
   level alone.

---

## 2. Background and Related Work

### 2.1 Agent Instruction Files

Agent instruction files are project-specific natural-language documents
that configure agent behavior. This study focuses on the two formats used
by coding agents with full tool access (shell, file system, network):

- **CLAUDE.md**: used by Claude Code (Anthropic). Loaded from the project
  root and parent directories; treated as context injected into the agent's
  system prompt.
- **AGENTS.md**: used by OpenAI Codex CLI. Similar role and structure.

We exclude copilot-instructions.md (GitHub Copilot) because Copilot
Workspace operates with more constrained tool access, making the
intent-behavior gap less relevant. These files have no formal schema.
Their content ranges from one-line directives ("never push to main") to
multi-page documents covering architecture, build instructions, testing
procedures, and coding standards.

### 2.2 Prior Empirical Studies

Five studies have examined agent instruction files empirically. We
summarize each below; a detailed methodology comparison is in Appendix A.

**Chatlatanagulchai et al. (2025a)** collected 253 CLAUDE.md files from 242
repositories and classified them into 15 topic categories at file
granularity. Two inspectors assigned labels per file (no Cohen's kappa
reported; 9.2% disagreement rate resolved by a third inspector). Top
categories: Build and Run (77.1%), Implementation Details (71.9%),
Architecture (64.8%), Security (8.7%).

**Chatlatanagulchai et al. (2025b)** expanded to 2,303 files across three
tools (Claude, Codex, Copilot). Manual labeling of a 332-file subset
(80.3% raw agreement, no kappa), followed by GPT-5 automated
classification of the full corpus (micro-avg F1 = 0.79). 16 topic
categories; Security 14.5%. The authors note examples of prohibitive
instructions but do not quantify their prevalence.

**Santos et al. (2025)** analyzed 328 CLAUDE.md files from top-100
repositories. Classification at section-heading level by a single author,
verified by two others in a meeting (no reliability metric). 9 SE concern
categories; Software Architecture (72.6%).

**Lulla et al. (2026)** measured the efficiency impact of AGENTS.md files
on 10 repositories / 124 PRs. AGENTS.md reduced median runtime by 28.64%
and output tokens by 16.58%. Compliance was explicitly not measured.

**Liu et al. (2026)** reverse-engineered Claude Code v2.1.88 and found that
CLAUDE.md is treated as context, not policy: there are no hard deny/allow
gates for CLAUDE.md directives. The paper cites Anthropic's internal data
showing a 93% permission-prompt approval rate (not independently verified).

### 2.3 Gaps in Prior Work

All prior corpus studies share three limitations that this study addresses:

**G1: File-level granularity.** Classification is applied to whole files or
section headings. No study extracts individual statements or counts
directives per file. A file classified as "Testing" may contain 1 testing rule or 20; the
studies cannot distinguish these cases.

**G2: Topic-based taxonomy.** Categories describe what a file is *about*
(Architecture, Security, Testing), not what it *demands* (describe,
instruct, constrain). A behavioral constraint like "run tests before
committing" falls under "Testing" alongside non-constraining content like
"the project uses Jest." The studies cannot separate the two.

**G3: No enforceability assessment.** No study asks whether a rule can be
enforced by a deterministic mechanism, or at which layer of the system
stack enforcement is possible.

---

## 3. Research Questions

We pose five research questions, organized from descriptive to analytical.

**RQ1 (Content types): What fraction of instruction-file content is
description vs. directive?**
Prior studies classify by topic but do not distinguish factual descriptions
("this project uses React") from directives ("always use TypeScript for new
files"). RQ1 establishes the base rate of directive content.

**RQ2 (Topic distribution): How do descriptions and directives distribute
across topic categories?**
We apply Chatlatanagulchai et al.'s 16 topic categories at statement level
and cross-tabulate with the description/directive distinction from RQ1.
This reveals how directives are distributed across topics that prior
studies report only at file level.

**RQ3 (Directive density): How many directives does each project contain,
and how are they distributed?**
Prior studies report file-level prevalence ("77% of files contain Build/Run
content") but not directive counts. RQ3 measures the number of directives
per project, enabling distribution analysis (median, mean, skewness).

**RQ4 (Enforceability): Which directives are enforceable, and at what
level?**
Following the intent/action/behavior framework, we assess each directive
at three levels:
- **Intent**: the directive can only be followed if the LLM retains it in
  context and complies probabilistically.
- **Action**: the directive can be checked deterministically by inspecting
  tool-call names and arguments at the agent-framework boundary.
- **Behavior**: the directive can be checked by observing OS-level
  operations (system calls) and their provenance across the process tree.
Within behavior-level directives, we further distinguish *per-event*
(checkable from a single system call) from *cross-object* (requiring
state accumulated across multiple events and objects).

**RQ5 (Enforcement requirements): What enforcement mechanisms do different
directive types require?**
For each directive subtype, we characterize the minimum enforcement level
required and the fraction that requires cross-object state tracking. This
enables a layered view of which directives are addressable by existing
mechanisms and which require mechanisms not yet deployed in practice.

---

## 4. Methodology

### 4.1 Dataset Construction

**Sampling frame.** We target public GitHub repositories that contain at
least one agent instruction file (CLAUDE.md or AGENTS.md) in a standard
location (repository root or `.claude/` directory).

**Search strategy.** We search for repositories in the AI agent ecosystem
via GitHub topic and keyword queries (e.g., `topic:ai-agent`,
`topic:coding-agent`, `topic:llm-agent`, `topic:mcp`) rather than
searching for CLAUDE.md files by filename. This targets projects whose
developers actively use coding agents in their development workflow,
producing more mature and substantive instruction files. A direct filename
search (as used by Chatlatanagulchai et al.) would include repositories
where CLAUDE.md was added experimentally or contains minimal content.
The full list of 15 search queries is recorded in the replication package
(`queries.log`).

**Filtering.** From the search results, we apply four exclusion criteria:

1. **Non-code repositories.** Repositories whose primary language is
   null or Markdown, or whose name/topics match documentation patterns
   (awesome-lists, tutorials, prompt collections, skill catalogs).
2. **Fake-star filtering.** The AI agent ecosystem has significant
   star inflation. We exclude repositories where forks > 0.8 × stars
   (fork-bot signal), stars > 40k with open issues < 20 (no community),
   or age < 2 months with stars > 40k (implausible growth). A manual
   blocklist covers confirmed fake/SEO repositories.
3. **Inactive repositories.** Repositories with no push activity within
   2 weeks of the snapshot date are excluded, ensuring the corpus reflects
   projects under active development with agents.
4. **Trivial content.** Instruction files smaller than 500 bytes (pointer
   files, empty stubs) are excluded. Where CLAUDE.md and AGENTS.md are
   byte-identical, the duplicate is counted once.

Critically, we do **not** exclude repositories based on whether they
contain behavioral directives. Repositories with zero directives (all
descriptions) remain in the corpus as honest data points in the
denominator.

All exclusions are logged with reasons (`exclusions.log`) for
reproducibility.

**Snapshot.** All files were collected on [DATE]. Repository metadata
(stars, primary language, creation date, last push date) was recorded at
collection time.

**Corpus statistics.** [TODO: fill]

| Statistic | Value |
|---|---|
| Repositories | TODO |
| Instruction files (after dedup) | TODO |
| Total lines | TODO |
| Median file size (bytes) | TODO |
| Primary languages represented | TODO |

### 4.2 Statement Extraction and Classification

**Definition.** A *statement* is a coherent unit of content in an
instruction file that expresses a single thought: one factual claim, one
directive, or one constraint. Statements may span one or more lines and
do not necessarily align with markdown structure (a single list item may
contain multiple statements; a statement may span a paragraph).

**Why not automated segmentation.** Mechanical splitting by markdown
structure (list items, paragraphs, sentences) produces poor results:
instruction files vary widely in formatting; a single list item may
contain multiple directives ("never commit secrets or push to main");
and context is often interleaved with directives in the same paragraph.
We therefore use LLM-based extraction, which identifies semantic
boundaries rather than syntactic ones.

**Extraction method.** We use a two-pass LLM pipeline. Both passes use
model [TODO] with temperature 0 and a fixed random seed for
reproducibility. The full prompts are included in the replication package.

**Pass 1: Extraction + classification.** The LLM reads the complete
instruction file and outputs a structured YAML document. Each extracted
statement is classified along both taxonomy axes and assessed for
enforceability. The output schema:

```yaml
file: "owner/repo/CLAUDE.md"
statements:
  - id: 0
    lines: [1, 3]             # half-open line range [start, end) in the original file
    text: "# Project CLAUDE.md\n\n"
    type: structural           # structural | description | directive
    topic: null

  - id: 1
    lines: [3, 4]
    text: "The backend uses Express with TypeScript."
    type: description
    topic: Architecture        # 16 categories from Chatlatanagulchai et al.
    # fields below apply only to directives:
    enforceability: null       # intent | action | behavior_per_event | behavior_cross_object
    confidence: null           # high | medium | low

  - id: 2
    lines: [15, 16]
    text: "Run the full test suite before committing."
    type: directive
    topic: Testing
    enforceability: behavior_cross_object
    confidence: high

  - id: 3
    lines: [22, 25]           # multi-line statement
    text: "Never commit secrets or credentials. Use environment variables for all sensitive configuration."
    type: directive
    topic: Security
    enforceability: behavior_cross_object
    confidence: high

  - id: 4
    lines: [30, 31]
    text: "Prefer const over let."
    type: directive
    topic: Implementation Details
    enforceability: intent
    confidence: high
```

The `lines` field records the half-open line range `[start, end)` in the
original file (1-indexed). The union of all line ranges for a file covers
lines 1 through N (total line count) with no gaps or overlaps, ensuring
every line is assigned to exactly one statement. Structural content
(markdown headers, blank lines, code blocks, formatting) is included as
statements with `type: structural`. The `text` field preserves the
original file content verbatim.

**Granularity rule.** The minimum unit is a line. Each line belongs to
exactly one statement; no sub-line splitting is performed. Multiple
consecutive lines may form a single statement, but a single line is
never split across statements. When a line contains multiple directives
with different topics (e.g., "Never commit secrets or push to main
directly"), the broader topic is assigned (Development Process rather
than Security). This avoids subjective sub-line segmentation at the
cost of slight topic imprecision, which we consider an acceptable
trade-off for mechanical verifiability. The prompt instructs the LLM to: (a) extract every distinct
statement with its line range, (b) classify each using the taxonomy
(Axis 1: type, Axis 2: topic, Axis 3: enforceability) following the
definitions in Sections 4.3 and 4.4, (c) assign a confidence level, and
(d) preserve the original text verbatim.

**Pass 2: Cross-validation.** A second LLM call reads the original file
together with the Pass 1 YAML and directly updates it: adding missed
statements, removing false extractions, and correcting classifications.
Each change is annotated with a `_review` field for auditability:

```yaml
file: "owner/repo/CLAUDE.md"
_review:
  pass1_count: 47
  added: 1
  removed: 1
  modified: 1
statements:
  - id: 2
    lines: [15, 16]
    text: "Run the full test suite before committing."
    type: directive
    topic: Testing
    enforceability: behavior_cross_object
    confidence: high

  # added by Pass 2 (was merged into id 14 in Pass 1)
  - id: 48
    lines: [67, 70]
    text: "Treat external input as untrusted."
    type: directive
    topic: Security
    enforceability: behavior_cross_object
    confidence: medium
    _review: "added: missed by Pass 1, embedded in security paragraph"

  # modified by Pass 2
  - id: 7
    lines: [28, 29]
    text: "Always run linter before pushing."
    type: directive
    topic: Development Process  # was: Implementation Details
    enforceability: behavior_cross_object
    confidence: medium
    _review: "modified topic: Implementation Details -> Development Process"

  # id 12 removed by Pass 2 (was a code example, not a statement)
```

The `_review` metadata block records Pass 2 statistics; per-statement
`_review` fields record individual changes. Statements without a
`_review` field were unchanged from Pass 1.

**Methodological metrics from the two-pass pipeline.** For the full
corpus, we report:
- Pass 2 addition rate: fraction of statements missed by Pass 1
  (estimates extraction recall).
- Pass 2 removal rate: fraction of Pass 1 extractions rejected
  (estimates extraction precision).
- Pass 2 modification rate: fraction of classifications changed
  (estimates classification stability).

**Manual validation.** A stratified random sample of [TODO: N] statements
(stratified by LLM-assigned type and subtype) is independently coded by
two human annotators using the same taxonomy. We report Cohen's kappa for
Axis 1 (description vs. directive), Axis 2 (topic category), and
Axis 3 (enforceability level). Disagreements are resolved by discussion; the
resolution and rationale are recorded.

### 4.3 Taxonomy

Each statement is classified along three dimensions.

**Axis 1: Content type** (speech-act distinction, following Searle 1976).

| Type | Definition | Example |
|---|---|---|
| **Structural** | Markdown formatting with no semantic content: headers, blank lines, code fences, horizontal rules. | `## Testing`, blank lines, `` ``` `` |
| **Description** | Factual statement about the project. Does not instruct the agent to do or avoid anything. | "The backend uses Express with TypeScript." |
| **Directive** | Statement that instructs the agent to perform, avoid, or condition an action. | "Run tests before committing." |

**Decision procedure.** If the segment is purely formatting (header, blank
line, code fence), it is structural. If the segment can be rephrased as an
imperative ("do X", "do not do X", "do X before Y"), it is a directive.
Otherwise it is a description.

**Axis 2: Topic category** (reused from Chatlatanagulchai et al. 2025b).

We adopt the 16-category topic scheme from the largest prior corpus study
to enable direct comparison. The categories are: System Overview, AI
Integration, Documentation, Architecture, Implementation Details, Build
and Run, Testing, Configuration & Environment, DevOps, Development
Process, Project Management, Maintenance, Debugging, Performance,
Security, UI/UX. Definitions and examples follow Chatlatanagulchai et al.
(2025b); the full coding guide is in the replication package.

Prior studies applied these categories at file level ("this file contains
Testing content"). We apply them at statement level ("this statement is
about Testing"). This enables cross-tabulation: for each topic category,
what fraction of statements are descriptions vs. directives? This
directly answers how behavioral directives are distributed across the
topic categories that prior studies report.

**Axis 3: Enforceability** (new, applied only to directives).

Assessed using the intent/action/behavior framework via the decision
procedure in Section 4.4. Levels: intent, action, behavior (per-event),
behavior (cross-object).

### 4.4 Enforceability Assessment

For each directive, we assess the minimum enforcement level required using
the intent/action/behavior framework and the following decision procedure.

**Step 1 (Action): Can the directive be checked from the tool-call record
alone?** A directive is enforceable at the *action* level if it can be
expressed as a predicate over a single tool-call record (tool name and
arguments), without reference to prior tool calls or OS-level state.
Example: "do not call the `delete_file` tool" is action-level. "Do not
delete files outside the working directory" is not, because the agent may
use `run_command("rm ...")` instead of `delete_file`.

**Step 2 (Behavior, per-event): Can the directive be checked from a single
OS event?** A directive is enforceable at *behavior, per-event* if it can
be expressed as a predicate over a single system call and its arguments,
but not over a single tool-call record. Example: "do not execute `rm -rf`"
requires matching `execve("rm", ["-rf", ...])` regardless of which tool
call produced it.

**Step 3 (Behavior, cross-object): Does the directive require state across
multiple OS events?** A directive is enforceable at *behavior, cross-object*
if checking it requires state accumulated across multiple system calls and
objects (processes, files, network endpoints). Example: "a process that has
read `.env` must not connect to an external endpoint" requires tracking
which files the process has read (accumulated state) and checking at the
`connect` event.

**Step 4 (Intent only): Is the directive only enforceable by LLM
compliance?** A directive is *intent-only* if it cannot be expressed as a
predicate over any observable system event. Example: "prefer descriptive
variable names" requires understanding code semantics, not system events.

**Assignment rule.** When a directive's enforceability depends on the tool
path the agent takes (e.g., "do not push to main" is action-level if done
via a dedicated tool call, but behavior-level if done via `bash -c`), we
assign the minimum level at which the directive can be *reliably enforced
across all tool paths*. This maps directly to the intent-behavior gap: the
gap between action and behavior is precisely the set of directives that
are action-level for some tool paths but behavior-level for others.

This procedure assigns each directive to exactly one level. Enforceability
is included in the inter-rater reliability assessment (Section 4.6).

### 4.5 Worked Examples

The following examples illustrate the full annotation pipeline from raw
text to final labels.

| Raw text | Lines | Axis 1 | Axis 2 (Topic) | Axis 3 (Enforceability) | Rationale |
|---|---|---|---|---|---|
| "The backend uses Express with TypeScript." | [3,3] | Description | Architecture | — | Factual; no imperative. |
| "Prefer `const` over `let`." | [12,12] | Directive | Implementation Details | Intent | Code idiom; no syscall signal. |
| "Run `npm install` before `npm run dev`." | [8,8] | Directive | Build and Run | Action | Tool-call argument matching suffices. |
| "Always explain your reasoning before making changes." | [45,45] | Directive | AI Integration | Intent | Agent-user interaction; no syscall signal. |
| "Run the full test suite before committing." | [15,15] | Directive | Testing | Behavior (cross-object) | Requires tracking test execution before commit. |
| "Never commit secrets or credentials." | [22,24] | Directive | Security | Behavior (cross-object) | Requires tracking file reads (secret source) before commit/push. |
| "Do not execute `rm -rf`." | [31,31] | Directive | Development Process | Behavior (per-event) | Single `execve` match. |
| "Do not push to main directly." | [18,18] | Directive | Development Process | Behavior (cross-object) | Action-level via tool call, but behavior-level via `bash -c`. Assignment rule: behavior. |

Two additional edge cases:

| Raw text | Lines | Axis 1 | Axis 2 (Topic) | Axis 3 | Rationale |
|---|---|---|---|---|---|
| "We use Jest. Always run `jest --coverage` before committing." | [9,9] | Split: Description + Directive | Testing / Testing | — / Behavior (cross-object) | Hybrid: split at sentence boundary into two statements. |
| "Do not make changes without explaining them first." | [52,52] | Directive | AI Integration | Intent | Agent-user interaction; "explaining" has no syscall signal. |

The "push to main" example illustrates an enforceability ambiguity: the
level depends on whether the agent uses the tool API or a shell. Per the
assignment rule in Section 4.4, we assign behavior-level (reliable across
all tool paths).

Note that the same topic category (e.g., Testing, Development Process)
can contain both descriptions and directives, and directives at different
enforceability levels. This is precisely the cross-tabulation that prior
file-level studies cannot produce.

### 4.6 Inter-Rater Reliability

Two annotators independently code a stratified random sample of [TODO: N]
statements. We report:

- Cohen's kappa for Axis 1 (description vs. directive).
- Cohen's kappa for Axis 2 (topic category, 16 categories).
- Cohen's kappa for Axis 3 (enforceability: intent, action, behavior).
- Cohen's kappa for per-event vs. cross-object (within behavior).

Target: kappa >= 0.7 (substantial agreement) for all dimensions. If kappa
falls below 0.6 for any dimension, we refine the coding guide and re-code.

---

## 5. Results

### 5.1 RQ1: Content Types

[TODO: Table showing desc vs directive counts and percentages, per-project
distribution]

### 5.2 RQ2: Directive Taxonomy

[TODO: Table showing directive subtype distribution. Comparison with prior
studies' topic-based categories — show how directives scatter across their
categories]

### 5.3 RQ3: Directive Density

[TODO: Histogram of directives per project. Median, mean, p25, p75. Comparison
with prior studies' file-level prevalence numbers]

### 5.4 RQ4: Enforceability

[TODO: Table showing enforceability breakdown: intent, action, behavior
(per-event), behavior (cross-object). Per directive subtype.]

### 5.5 RQ5: Enforcement Requirements

[TODO: Contingency table of directive subtype × enforcement level. For each
subtype, report the fraction at each level (intent, action, behavior
per-event, behavior cross-object). This table directly maps the
intent/action/behavior framework to empirical data.]

---

## 6. Discussion

### 6.1 Descriptions vs. Directives: A Missing Distinction

[TODO: Discuss how the desc/directive split changes our understanding of
instruction files compared to prior topic-based studies. Show concrete
examples where a single topic category (e.g., "Testing") contains both
descriptions and directives that have fundamentally different enforcement
implications.]

### 6.2 The Cross-Object Enforcement Gap

[TODO: Discuss the RQ5 finding. What fraction of directives falls in the
gap? What types of directives are most common in the gap? What does this
imply for harness engineering?]

### 6.3 Implications for Agent Harness Design

[TODO: Connect findings to the three enforcement levels. Discuss:
- Style directives are enforceable only at the intent level.
- Build/tooling directives are often enforceable at the action level.
- Communication directives are mostly enforceable only at the intent level.
- Constraint directives frequently require enforcement at the behavior
  level, especially when they involve ordering, scoping, or data-flow
  conditions.
- Cross-object constraints specifically require state tracking across
  process, file, and network boundaries at the behavior level.]

### 6.4 Limitations of LLM-Assisted Classification

[TODO: Discuss the reliance on LLM for rule classification. Report
agreement between LLM and human annotators on the validation sample.
Compare with Chatlatanagulchai et al. (2025b) who used GPT-5 with
F1=0.79. Discuss failure modes.]

---

## 7. Related Work

### 7.1 Empirical Studies of Agent Instruction Files

[Summarize the five prior studies with focus on methodology comparison.
Reference Appendix A for detailed comparison table.]

### 7.2 Agent Harnesses and Guardrails

[Discuss the agent harness concept (Agent = Model + Harness) and how this
study informs the enforcement component of harnesses. Reference AgentSpec,
Progent, FIDES, CaMeL as enforcement systems that this study's findings
can guide.]

### 7.3 Information-Flow Control and OS Enforcement

[Brief positioning against CamQuery, Tetragon, and similar systems as
potential enforcement mechanisms for cross-object directives.]

---

## 8. Threats to Validity

### 8.1 Construct Validity

- The desc/directive distinction and directive subtypes are defined by the
  authors. Alternative taxonomies are possible. The Axis 1 split draws on
  speech-act theory (constative vs. directive) but we do not claim
  linguistic completeness.
- Enforceability is assessed via the decision procedure in Section 4.4,
  not by empirical testing against deployed enforcement systems. The
  assessment reflects the authors' understanding of existing mechanisms.
- LLM-assisted classification introduces model-specific bias. Different
  LLMs may segment and classify differently; no sensitivity analysis
  across models is performed.
- **Researcher bias.** The authors also develop an OS-level enforcement
  system (ActPlane). The taxonomy and enforceability criteria may be
  unintentionally skewed toward enforceable directives. We mitigate this
  through the decision procedure (Section 4.4) and inter-rater reliability
  (Section 4.6), but acknowledge the risk.

### 8.2 Internal Validity

- Inter-rater reliability (Cohen's kappa) is computed on a sample, not the
  full dataset. Sample size and stratification affect generalizability.
- Statement extraction depends on markdown parsing heuristics; malformed
  files may lose statements.

### 8.3 External Validity

- Star-based sampling biases toward well-maintained, popular projects.
  Instruction files in less popular or private repositories may differ.
- Only two file types (CLAUDE.md, AGENTS.md)
  are included. Other agent configuration mechanisms (settings files, MCP
  configs, system prompts) are excluded.
- Single-time-point snapshot. Instruction files evolve rapidly
  (Chatlatanagulchai et al. report median 1--3 day update intervals).
- English-language bias. Non-English instruction files are excluded.

---

## 9. Conclusion

[TODO: Summarize findings for RQ1-RQ5. State the main takeaway: agent
instruction files contain a substantial fraction of directives (not just
descriptions), these directives span multiple enforcement levels, and a
meaningful subset falls into an enforcement gap between tool-call guards
and OS-level mechanisms. Release the annotated dataset for future work.]

---

## Appendix A: Detailed Methodology Comparison with Prior Studies

[TODO: Include the full comparison table from empirical_study_survey.md
Section 7.1, expanded with ActPlane's methodology column updated to
reflect this paper's design.]
