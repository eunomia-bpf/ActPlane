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
We therefore use LLM-agent-based extraction, which identifies semantic
boundaries rather than syntactic ones.

**Extraction method.** We use a two-pass LLM agent pipeline. Both passes use
model (Claude Opus 4.6) with temperature 0 and a fixed random seed for
reproducibility. The full prompts are included in the replication package.

**Pass 1: Extraction + classification.** The LLM agent reads the complete
instruction file and outputs a structured YAML document. Each extracted
statement is classified along both taxonomy axes and assessed for
enforceability. The output schema:

```yaml
file: "owner/repo/CLAUDE.md"
statements:
  - id: 1
    lines: [1, 4]             # half-open line range [start, end), includes header + blank line
    text: "# Project CLAUDE.md\n\nThe backend uses Express with TypeScript."
    type: description          # description | directive
    topic: Architecture        # 16 categories from Chatlatanagulchai et al.
    # fields below apply only to directives:
    enforceability: null       # semantic_only | content | per_event | cross_event
    context_required: null     # none | project | task (Axis 4, system-level directives only)
    confidence: null           # high | medium | low

  - id: 2
    lines: [15, 16]
    text: "Run the full test suite before committing."
    type: directive
    topic: Testing
    enforceability: cross_event
    context_required: project  # "test suite" = pytest? jest? project-specific
    confidence: high

  - id: 3
    lines: [22, 25]           # multi-line statement
    text: "Never commit secrets or credentials. Use environment variables for all sensitive configuration."
    type: directive
    topic: Security
    enforceability: cross_event
    context_required: project   # "secrets" / "credentials" unresolved — which files?
    confidence: high

  - id: 4
    lines: [30, 31]
    text: "Prefer const over let."
    type: directive
    topic: Implementation Details
    enforceability: content
    context_required: none     # "const"/"let" is explicit in the directive
    confidence: high
```

The `lines` field records the half-open line range `[start, end)` in the
original file (1-indexed). The union of all line ranges for a file covers
lines 1 through N (total line count) with no gaps or overlaps, ensuring
every line is assigned to exactly one statement. The `text` field
preserves the original file content verbatim, including any headers,
blank lines, or formatting that fall within the line range.

**YAML formatting rules.** The `text` field uses YAML block scalar (`|`)
syntax. The text content must exactly match the source file lines for the
specified range. Quoted strings with `\n` escapes are not used.
Automated scripts must not be used to fill the `text` field; all
annotation is manual to ensure the annotator has read and classified each
statement. A validation script (`validate.py`) checks line-range
coverage (no gaps, no overlaps) and text fidelity (content matches source
after stripping whitespace) for every `statements.yaml` file.

**No batch or pattern-based annotation.** All classification — including
Axis 3 (enforcement level) and Axis 4 (context requirement) — must be
performed by reading each directive individually and applying the
decision procedure. Regular expressions, keyword matching, or other
pattern-based heuristics must not be used to assign labels in bulk.
The decision procedure requires semantic judgment (e.g., whether
"upstream source" maps to a concrete path requires understanding the
project, not matching a regex). The LLM agent prompt explicitly
instructs the model to read each statement, reason about it, and
assign the label; batch shortcuts are prohibited.

**Granularity rules.**

- *Default: one line, one statement.* When source lines are
  independently meaningful (e.g., list items, standalone sentences),
  each line is a separate statement by default. Lines are merged into
  a single statement only when they form a single coherent thought that
  cannot be meaningfully split: a sentence continued across lines, a
  code block with its introductory text, a describtive list of files
  or a multi-line directive that
  expresses one constraint. The burden of proof is on merging, not on
  splitting. In particular, a list of directives under a shared section
  header (e.g., "Style Guide / General Principles") produces one
  statement per list item, not one statement for the entire section.
- *Minimum unit is a line.* Each line belongs to exactly one statement;
  no sub-line splitting is performed. When a line contains multiple
  directives with different topics (e.g., "Never commit secrets or push
  to main directly"), the broader topic is assigned.
- *Formatting is absorbed, not standalone.* Headers, blank lines,
  horizontal rules, HTML comments, and decorative elements (ASCII art
  boxes, emoji markers) belong to the statement they introduce or
  accompany. A section header belongs to the next statement; trailing
  blank lines belong to the preceding statement.
- *Semantically coherent blocks are one statement.* A list or table that
  expresses a single thought (e.g., a file-structure listing, a
  dependency list, a command reference table) is one statement spanning
  all its lines, not one statement per line. If rows in a table have
  different types (some description, some directive), each group of
  same-type rows is a separate statement. This rule applies only to
  descriptive enumerations (directory listings, dependency tables); it
  does not override the default split for independent directives.
- *Code blocks belong to their surrounding statement.* A code block
  that illustrates a directive (e.g., build commands following "Run
  these commands:") is part of that directive. A standalone code block
  (e.g., a file tree) is part of a description.
- *Compound directives with the same topic stay together.* "Never log,
  commit, or expose API keys" is one directive (topic: Security), not
  three. This applies only when a single sentence expresses multiple
  related constraints; separate list items are separate statements even
  if they share the same topic.
- *Lists of independent directives remain separate.* A list where each
  item is a self-contained directive (e.g., "Do not create git stash /
  Do not switch branches / Do not modify worktrees") produces one
  statement per item, because each has independent enforceability.
  This is the common case for markdown list items under a section
  header; merging list items into one statement requires explicit
  justification (e.g., they jointly define a single workflow step).
- *External references are directives.* Lines that point the agent to
  another file ("See AGENT\_INSTRUCTIONS.md for full instructions") are
  directives. The referenced file's content is not analyzed, but the
  reference itself is a statement.
- *Changelogs and version history are descriptions.* Changelog blocks
  are one description statement spanning the entire block. The prompt instructs the LLM agent to: (a) extract every distinct
statement with its line range, (b) classify each using the taxonomy
(Axis 1: type, Axis 2: topic, Axis 3: enforcement level) following the
definitions in Sections 4.3 and 4.4, (c) assign a confidence level, and
(d) preserve the original text verbatim.

**Pass 2: Cross-validation.** A second LLM agent call reads the original file
together with the Pass 1 YAML and directly updates it: adding missed
statements, removing false extractions, and correcting classifications.

**Manual validation.** A stratified random sample of 100 statements
(stratified by agent-assigned type and subtype) is independently examed by
 human annotators using the same taxonomy. Disagreements are resolved by discussion; the
resolution and rationale are recorded.

### 4.3 Taxonomy

Each statement is classified along four dimensions.

**Axis 1: Content type** (speech-act distinction, following Searle 1976).

| Type | Definition | Example |
|---|---|---|
| **Description** | Factual statement about the project. Does not instruct the agent to do or avoid anything. | "The backend uses Express with TypeScript." |
| **Directive** | Statement that instructs the agent to perform, avoid, or condition an action. | "Run tests before committing." |

There is no separate "structural" category. Formatting elements (headers,
blank lines, horizontal rules, HTML comments, decorative ASCII art) are
absorbed into the statement they introduce or accompany. A section header
like `## Testing` belongs to the next statement. Blank lines between
statements belong to the preceding statement. This ensures every line is
classified as part of a description or directive without a third category.

**Decision procedure.** If the statement (ignoring formatting) can be
rephrased as an imperative ("do X", "do not do X", "do X before Y"), it
is a directive. Otherwise it is a description.

**Axis 2: Topic category** (adapted from Chatlatanagulchai et al. 2025b).

We start from the 16-category topic scheme of Chatlatanagulchai et al.
(2025b) and collapse four sparse categories (each n < 30 at
statement level) into their closest parent, yielding 12 analysis
categories: Debugging and Project Management are merged into Development
Process; Performance and UI/UX are merged into Implementation Details.
The resulting 12 categories are: System Overview, AI Integration,
Documentation, Architecture, Implementation Details, Build and Run,
Testing, Configuration & Environment, DevOps, Development Process,
Maintenance, Security. Definitions follow Chatlatanagulchai et al.
(2025b); the full coding guide is in the replication package.

Prior studies applied these categories at file level ("this file contains
Testing content"). We apply them at statement level ("this statement is
about Testing"). This enables cross-tabulation: for each topic category,
what fraction of statements are descriptions vs. directives? This
directly answers how behavioral directives are distributed across the
topic categories that prior studies report.

**Axis 3: Enforcement level** (new, applied only to directives).

Each directive is classified by the enforcement mechanism it requires.
The classification follows a waterfall decision procedure (Figure 0):
each directive enters at the top and exits at the first level whose
predicate it satisfies.

```
Directive
  │
  ▼
┌─────────────────────────────────────┐
│ Q1: Involves system-level behavior? │
│ (files / commands / network)        │
└──────────┬──────────────────────────┘
           │
      No ──┼──► semantic-only
           │    "Be concise." / "Explain reasoning."
      Yes  │
           ▼
┌─────────────────────────────────────┐
│ Q2: Requires static file content    │
│     inspection or system events?    │
│ (code style / naming / format)      │
└──────────┬──────────────────────────┘
           │
      Yes ─┼──► content
           │    "Prefer const over let." / "Use type hints."
      No   │
           ▼
┌─────────────────────────────────────┐
│ Q3: Decidable from a single         │
│     system operation or multiple?   │
│ (one execve / open / connect)       │
└──────────┬──────────────────────────┘
           │
      Yes ─┼──► per-event
           │    "Never push to main." / "Don't rm -rf."
      No   │
           ▼
┌─────────────────────────────────────┐
│ Q4: Requires state across           │
│     multiple operations             │
│ (history / lineage / ordering)      │
└──────────┬──────────────────────────┘
           │
           ┼──► cross-event
                "Run tests before committing."
                "Process that read .env must not connect."
```
*Figure 0. Enforcement-level waterfall. Each directive exits at the
first matching level; the four levels are mutually exclusive and ordered
by enforcement complexity.*

| Level | Definition | Example |
|---|---|---|
| **Semantic-only** | Directive governs only the agent's reasoning, communication, or output presentation. No system-level observable counterpart. | "Always explain your reasoning." / "Be concise." / "Report the full URL at end of task." |
| **Content** | Directive imposes requirements on the *content* of files the agent reads or writes. Enforcement requires inspecting file content, not just the file-access event itself. | "Prefer `const` over `let`." / "Use type hints." / "Commit format: `type(scope): message`." |
| **Per-event** | Directive can be checked by matching a single system operation (command execution, file access, network connection) against a pattern. An agent reading the repository context can determine the concrete pattern. | "Do not run `rm -rf`." / "Never push to main." / "Do not create git worktree." / "Never modify vendor/ files." |
| **Cross-event** | Directive requires state accumulated across multiple system operations. | "A process that read `.env` must not connect to external endpoints." / "Run tests before committing." / "Only modify DB through the migration tool." |

**Axis 4: Context requirement** (new, applied only to system-level directives).

Each system-level directive (content, per-event, or cross-event) is
classified by what additional context an enforcement mechanism needs
beyond the directive text itself to evaluate the rule.

| Level | Definition | Example (from corpus) |
|---|---|---|
| **None** | The directive text is self-contained: all commands, paths, patterns, or constraints needed to write the enforcement rule are explicit in the text. No external lookup required. | "Do not execute `rm -rf`." / "Do not create git worktree." / "Never run `bun publish` directly." (command is explicit) / "NEVER squash merge or rebase merge PRs." (merge strategy is explicit) / "Prefer `const` over `let`." |
| **Project context** | The directive contains an unresolved reference that must be looked up in the repository before the rule can be enforced. An agent can derive this context by reading the repository. | "Run the full test suite before committing." (test suite = `pnpm test:changed`? `pytest`? `bun test`? — must read repo) / "Never modify upstream source code." (upstream = which paths? `vendor/`? `lib/`? — must read repo) / "Run linting before push." (linter = ruff? eslint? clippy? — must read repo) |
| **Task context** | The directive depends on information that changes per invocation — the current user request, whether approval was granted, what the agent is trying to accomplish — and cannot be resolved from the repository alone. | "Do not update dependencies without approval." (was approval given this session?) / "Keep changes focused." (focused on what? depends on current task) / "Do not delete/rename unexpected files; ask if blocking." (what is "unexpected"? depends on current task) / "Unless explicitly requested, prefer stacked commits over amend." (was it requested?) |

The classification is about **information completeness**, not about
whether the rule is universal or project-specific. A directive that
names a project-specific command verbatim ("never run `bun publish`
directly") is **none** because the enforcement pattern (`bun publish`)
is already explicit in the text. A directive that uses a universal
concept but leaves a parameter unresolved ("run the test suite before
committing") is **project** because "test suite" must be resolved to a
concrete command by reading the repository.

**Decision procedure for Axis 4.** The classification follows a
waterfall analogous to Figure 0 (Figure 0b).

```
System-level directive
  │
  ▼
┌─────────────────────────────────────┐
│ Q1: Does the directive text contain │
│ all information needed to write the │
│ enforcement rule?                   │
└──────────┬──────────────────────────┘
           │
      Yes ─┼──► none
           │
      No   │
           ▼
┌─────────────────────────────────────┐
│ Q2: Can the missing information be  │
│ resolved by reading the repository? │
└──────────┬──────────────────────────┘
           │
      Yes ─┼──► project context
           │
      No   │
           ▼
           ──► task context
```
*Figure 0b. Context-requirement waterfall.*

**Compound context.** A directive that requires both project and task
context is classified by the strongest (most dynamic) requirement.
For example, "only modify files related to your current task" requires
project context (which files exist) and task context (what is the
current task); it is classified as **task context** because the task
dependency is the binding constraint.

Four clarifications for borderline cases:

- *Explicit project-specific patterns are none.* A directive that
  spells out a project-specific command, path, or name verbatim is
  **none**, not project. "Never run `bun publish` directly" is none
  because `bun publish` is already the concrete enforcement pattern.
  "Run the test suite before committing" is project because "test
  suite" must be resolved. The test is whether the directive text
  itself is sufficient, not whether the rule is universal.
- *Unresolved domain concepts are project.* A directive like "never
  commit secrets or credentials" is **project**, not none: "secrets"
  and "credentials" are unresolved — which files or patterns constitute
  secrets depends on the project. By contrast, "never commit `.env`,
  `id_rsa`, or files matching `**/credentials/**`" is **none** because
  the patterns are explicit.
- *Approval gates.* Directives containing "unless explicitly
  requested/asked/approved/instructed", "without user approval", or
  "only when the user asks" are **task context**: they gate on a
  per-session user decision that cannot be derived from the repository.
- *Scope-relative constraints.* Directives like "only modify what is
  needed", "keep changes focused", "do not touch unrelated code", or
  "do not make unnecessary changes" are **task context**: what counts
  as "needed", "focused", "related", or "necessary" depends on what the
  user asked the agent to do in the current session. Note: coding
  idioms that use similar language ("avoid explicit type annotations
  unless necessary for exports") are **none** — "necessary" has a
  well-defined meaning in the language community independent of the
  task.

The three levels are ordered by dynamism: none is static, project
context changes per-repository but is stable within a session, task
context changes per-invocation. This directly informs the policy
lifecycle: none → hardcoded rules; project context → agent generates
rules by reading the repo (ActPlane RQ2); task context → agent must
generate or adapt rules per task at runtime (the "control plane"
argument).

### 4.4 Enforcement-Level Assessment

For each directive, we assess the enforcement level using the waterfall
decision procedure shown in Figure 0. The directive enters at Q1 and
exits at the first level whose predicate it satisfies.

**Q1: Does the directive relate to any system-level behavior?**
A directive relates to system-level behavior if it concerns commands
executed, files accessed or modified, network connections, or process
lifecycle. Even if stated abstractly (e.g., "never modify upstream
source"), it is system-level if an agent reading the repository context
can map it to concrete system operations (e.g., "upstream" = files in
`vendor/` directory). If the directive relates ONLY to the agent's
reasoning, communication, or output presentation, it is
**semantic-only**.

Three clarifications for conditional directives:

- *Abstractly-scoped system constraints.* A directive like "when SDK
  changes, run the build script" is system-level if "SDK" can be
  resolved to concrete file paths by reading the repository context
  (e.g., `packages/sdk/**`). Genuinely vague conditions ("when
  necessary", "when appropriate") that cannot be mapped to observable
  state are **semantic-only**.
- *Agent tool calls are observable operations.* MCP tool invocations,
  skill calls, and other agent-framework tool calls produce IPC or
  network events and are therefore system-level, not semantic-only. A
  pure tool-routing preference ("use `nx_workspace` tool first") is
  **per-event**. An ordering constraint on tool calls ("call
  `fetch-docs` MCP tool before writing integration code") is
  **cross-event**.
- *Exception conditions involving conversation state.* A directive like
  "do not commit without explicit user request" has a system-level core
  constraint (match `git commit`) with a conversation-level exception.
  The enforcement level is determined by the core constraint
  (**per-event** in this case), not by the exception. The enforcement
  mechanism defaults to blocking the operation; the exception is handled
  as a permission grant.

**Q2 (for system-level directives): Does enforcement require inspecting
file content?** If the directive imposes requirements on the text content
of files the agent reads or writes (code style, formatting, naming
conventions, commit message format), it is **content**. The
distinguishing feature: enforcement requires reading the file and parsing
its content, not just observing the file-access system call.

**Q3: Can the rule be matched from a single system operation?**
If the directive can be checked by matching one command execution, one
file access, or one network connection against a pattern derivable from
the repository context, it is **per-event**. Examples: matching
`execve("git", ["worktree", ...])`, matching `open("vendor/...")`,
matching `connect(external_ip)`.

**Q4: Does matching require state across multiple operations?**
If checking the directive requires knowing what happened before the
current operation (which files were previously read, which commands
previously ran, the process lineage), it is **cross-event**.

**Compound directives.** A directive that combines multiple
sub-constraints at different levels is classified by the strongest
(hardest to enforce) sub-constraint. For example, "read `cli/README.md`
and verify command help/output behavior alongside unit tests" contains
a semantic-only sub-constraint (read a file) and a cross-event
sub-constraint (verify behavior matches tests after changes); the
directive is classified as **cross-event**.

This procedure assigns each directive to exactly one level.
Enforcement level is included in the inter-rater reliability assessment
(Section 4.6).

### 4.5 Worked Examples

The following examples illustrate the full annotation pipeline from raw
text to final labels.

| Raw text | Axis 1 | Axis 2 (Topic) | Axis 3 (Enforcement) | Axis 4 (Context) | Rationale |
|---|---|---|---|---|---|
| "The backend uses Express with TypeScript." | Description | Architecture | — | — | Factual; no imperative. |
| "Always explain your reasoning before making changes." | Directive | AI Integration | Semantic-only | — | Purely agent-user communication. |
| "Be concise in responses." | Directive | AI Integration | Semantic-only | — | Purely output style. |
| "Prefer `const` over `let`." | Directive | Implementation Details | Content | None | `const`/`let` is explicit in the directive. |
| "Do not execute `rm -rf`." | Directive | Development Process | Per-event | None | Command pattern is explicit. |
| "Do not create git worktree." | Directive | Development Process | Per-event | None | Command pattern is explicit. |
| "Never push to main directly." | Directive | Development Process | Per-event | None | "main" is literal; enforcement pattern is explicit. |
| "Never run `bun publish` directly." | Directive | Development Process | Per-event | None | Project-specific command, but spelled out verbatim — enforcement pattern is self-contained. |
| "NEVER squash merge or rebase merge PRs." | Directive | Development Process | Per-event | None | Merge strategy is explicit (`--squash`, `--rebase`); no lookup needed. |
| "Author: OthmanAdi only. NEVER add `Co-Authored-By:` trailers." | Directive | Development Process | Content | None | Author name and trailer pattern are explicit in the directive text. |
| "Never modify upstream source code." | Directive | Development Process | Per-event | Project | "upstream" is unresolved — which paths? `vendor/`? `lib/`? Must read repo. |
| "Run the full test suite before committing." | Directive | Testing | Cross-event | Project | "test suite" is unresolved — pytest? jest? bun test? Must read repo. |
| "Run linting before push." | Directive | Development Process | Cross-event | Project | "linting" is unresolved — ruff? eslint? clippy? Must read repo. |
| "Only modify DB through the migration tool." | Directive | Development Process | Cross-event | Project | DB path + migration tool name are unresolved; must read repo. |
| "Do not update dependencies without approval." | Directive | Maintenance | Per-event | Task | "approval" = user said OK in this session; per-invocation. |
| "Keep changes focused." | Directive | Development Process | Per-event | Task | "focused" on what? Depends on current task. |
| "Unless explicitly requested, prefer stacked commits over amend." | Directive | Development Process | Per-event | Task | "explicitly requested" = per-session user intent. |
| "Never commit secrets or credentials." | Directive | Security | Cross-event | Project | "secrets" and "credentials" are unresolved — which files/patterns? `.env`? `id_rsa`? Must know the project's secret layout. |
| "Never commit `.env`, `id_rsa`, or files matching `**/credentials/**`." | Directive | Security | Cross-event | None | Patterns are explicit in the directive text; no lookup needed. |

Edge cases:

| Raw text | Axis 1 | Topic | Enforcement level | Rationale |
|---|---|---|---|---|
| "We use Jest. Always run `jest --coverage` before committing." | Split: Description + Directive | Testing / Testing | — / Cross-event | Hybrid: two statements at sentence boundary. |
| "Do not make changes without explaining them first." | Directive | AI Integration | Semantic-only | "Explaining" is purely conversational. |
| "When answering questions, verify in code; do not guess." | Directive | AI Integration | Semantic-only | Reasoning strategy, no system observable. |

Note that the same topic category (e.g., Development Process) can
contain directives at every enforcement level: content ("commit
format"), per-event ("don't create worktree"), cross-event ("only
through migration tool"). This is precisely the cross-tabulation that
prior file-level studies cannot produce.

