# Enforceability Classification Review (Round 2)

## Repos Reviewed (10)

1. **openai/codex** (85 statements) -- large Rust project with extensive TUI, API, and testing guidelines
2. **google/adk-python** (10 statements) -- Agent Development Kit, skill-based navigation
3. **charmbracelet/crush** (43 statements) -- Go TUI coding assistant
4. **vxcontrol/pentagi** (16 statements) -- security testing platform (Go + React)
5. **Kilo-Org/kilocode** (67 statements) -- forked AI coding CLI (TS/Bun monorepo)
6. **langchain-ai/open-swe** (33 statements) -- LangGraph-based coding agent
7. **browser-use/browser-harness** (5 statements) -- CDP browser harness
8. **ruvnet/ruflo** (65 statements) -- Claude Flow swarm orchestration
9. **NousResearch/hermes-agent** (54 statements) -- multi-platform AI agent (Python)
10. **rtk-ai/rtk** (45 statements) -- Rust CLI token optimizer

---

## Disagreements

### openai/codex

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 4 | behavior_per_event | behavior_cross_object | "Install any commands the repo relies on... if they aren't already available before running instructions here." | This is conditional on whether tools are already installed (requires checking existing state), plus it gates subsequent commands. However, each install command is itself a single event. On reflection the "if they aren't already available" condition is a pre-check that makes this cross_object (check availability, then install). Borderline -- could go either way. **Weak disagreement.** |
| 5 | behavior_per_event | behavior_linter | "Never add or modify any code related to CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR..." | This is about code content -- detecting references to specific env var names in source files. That requires inspecting file content, not just matching a system operation. Should be behavior_linter. |
| 15 | behavior_per_event | behavior_linter | "Do not add general product or user-facing documentation to the docs/ folder." | While this involves file path pattern matching (writes to docs/), the directive also requires judging whether content is "general product or user-facing documentation" vs. "app-server API documentation." This content-level judgment makes it behavior_linter. A pure path-based rule would be per_event, but the exception clause requires content inspection. |
| 22 | behavior_linter | behavior_cross_object | "If you add include_str!, include_bytes!... update the crate's BUILD.bazel..." | This is a cross-object constraint: IF you add certain macros in Rust code, THEN you must also update BUILD.bazel. It requires correlating changes across two files. |
| 25 | behavior_cross_object | intent | "When running Rust commands... be patient with the command and never try to kill them using the PID." | "Be patient" is purely about agent reasoning/strategy. The "never kill using PID" part could be per_event (blocking a kill command), but the framing is about patience/strategy. The compound should be classified by the strongest sub-constraint, which is per_event for the kill prohibition. **Suggest behavior_per_event** rather than cross_object. There is no cross-object state tracking needed. |
| 28 | intent | behavior_per_event | "resist adding code to codex-core" | This is about where files are created/modified -- specifically not adding code to a particular crate path. While "resist" is soft language, the operational constraint is about file write targets (behavior_per_event: file path pattern). However, the word "resist" implies judgment rather than a hard block. **Current label is defensible as intent due to soft language.** Retracted. |
| 46 | behavior_linter | behavior_cross_object | "any change that affects user-visible UI... must include corresponding insta snapshot coverage" | This requires correlating two things: (1) UI-affecting code changes and (2) the presence of snapshot tests. Classic cross_object. |
| 48 | behavior_per_event | intent | "If you don't have the tool: cargo install --locked cargo-insta" | This is informational guidance ("if you need it, here's how to install"). It's a pointer/instruction, not a directive to enforce. More accurately a description or intent. |
| 64 | behavior_per_event | behavior_linter | "All active API development should happen in app-server v2. Do not add new API surface area to v1." | Determining whether code constitutes "new API surface area" and whether it targets v1 vs v2 requires inspecting code content and understanding module structure. This is behavior_linter. |
| 71 | behavior_cross_object | behavior_linter | "Keep Rust and TS wire renames aligned. If a field uses #[serde(rename)], add matching #[ts(rename)]." | While this spans two annotations, they are in the same struct definition / same file. It's about code content consistency within a type definition, which a linter can check. This is behavior_linter. |

### google/adk-python

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 2 | behavior_per_event | intent | "For all matters regarding ADK development, please use the appropriate skill" | This is a navigation pointer telling the agent where to look for information. It's about conversation strategy, not an observable system operation. Should be intent. |
| 3 | behavior_per_event | intent | "adk-architecture: Use this skill whenever you need to understand the architecture..." | Same as above -- this is a pointer to read a skill file for context. The directive is about when to consult documentation, which is pure reasoning/strategy guidance (intent). If it said "always invoke the adk-architecture skill tool before modifying core APIs," that would be per_event. But "use this skill" for understanding is intent. |
| 4 | behavior_per_event | intent | "adk-style: Use this skill whenever writing code, tests, or reviewing PRs..." | Same pattern -- "read this file for guidelines." This is a navigation pointer (intent). |
| 5 | behavior_per_event | intent | "adk-git: Use this skill for any git operation..." | Same pattern. |
| 6 | behavior_per_event | intent | "adk-sample-creator: Use this skill when creating new samples..." | Same pattern. |
| 10 | behavior_per_event | intent | "Please refer to the adk-setup skill for detailed instructions." | Pure navigation pointer. |

**Note:** The google/adk-python file classifies all skill-reference directives as behavior_per_event, but they are all "use/refer to this document" navigation pointers. Per the rules, "Pure navigation pointers ('see X file', 'read X docs') = intent." These should all be intent.

### charmbracelet/crush

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 17-23 | behavior_per_event | description (or intent) | "Build: go build...", "Test: task test...", "Update Golden Files...", etc. | These are descriptions of available commands, not directives to use specific commands. They are formatted as reference information. The type is already "directive" but the content reads as "here's how to do X" rather than "you must do X." Enforceability classification as per_event is acceptable if we treat them as "use these specific commands" directives -- each can be checked as a single tool invocation. **Current labels are acceptable.** |
| 39 | behavior_cross_object | behavior_per_event | "ALWAYS format any Go code you write." + fallback chain | The core directive is "always run a formatter." Each formatting invocation is a single event. The fallback chain (try gofumpt, then goimports, then gofmt) is just a preference order, not a cross-object correlation. Should be behavior_per_event. The "ALWAYS" means checking that formatting was run, which could be cross_object (did you format after editing?). Actually, "always format Go code you write" requires correlating "wrote Go code" with "ran formatter" -- that IS cross_object. **Current label is correct.** Retracted. |
| 43 | intent | behavior_per_event | "Anytime you need to work on the TUI, read internal/ui/AGENTS.md before starting work." | Per the rules, this is a navigation pointer ("read X docs") = intent. But it has a conditional ordering constraint: "before starting work." That makes it cross_object (read file, then do work). However, "read a file" is an internal reasoning action, not an observable system operation in the enforcement sense. **Current label (intent) is correct.** |

### vxcontrol/pentagi

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 2 | intent | behavior_linter | "Always use English for all interactions, responses, explanations, and questions" | The output language of generated code comments, documentation, and commit messages can be checked by a linter (language detection). However, "interactions" and "responses" are conversation-level, which is truly intent. The compound directive spans both code artifacts (linter-checkable) and conversation (intent). Since "intent" is the weakest and the rules say "classify by strongest sub-constraint," this should be **behavior_linter** for the code-facing parts. But the primary thrust is about conversation language, making intent reasonable. **Borderline -- current label acceptable.** |
| 15 | behavior_per_event | behavior_cross_object | "When modifying schema.graphqls, re-run gqlgen... When modifying REST handler annotations, re-run swag... When modifying frontend GraphQL queries, re-run npm run graphql:generate." | These are all conditional: IF you change X, THEN run Y. Each requires correlating a file modification with a subsequent command. Classic cross_object. |

### Kilo-Org/kilocode

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 2 | intent | behavior_per_event | "ALWAYS USE PARALLEL TOOLS WHEN APPLICABLE" | This tells the agent to use parallel tool calls. Agent tool call patterns are observable operations. However, "when applicable" introduces subjective judgment about when parallelism applies, which is intent-level. **Current label is defensible.** |
| 17 | behavior_per_event | behavior_linter | "every Kilo-specific change in shared opencode files must be annotated with kilocode_change markers" | This requires inspecting file content to determine whether changes are annotated with specific markers. That's content inspection = behavior_linter. |
| 26 | behavior_per_event | behavior_linter | "Extension-specific settings should live in the Kilo extension settings, not default VS Code settings" | Determining whether a setting is "extension-specific" and where it's placed requires content inspection of configuration files. behavior_linter. |
| 54 | behavior_linter | intent | "When creating or managing GitHub issues... load .kilo/skills/gh-issues/SKILL.md" | This is a navigation pointer -- "load/read this file before doing X." Per the rules, this is intent. |
| 56 | behavior_per_event | intent | "when planning or coding, update shared files with OpenCode as last resort!" | "Last resort" is a subjective judgment call about when to modify shared files. This is strategic guidance (intent), not a pattern-matchable operation. |
| 59 | intent | behavior_linter | "Minimize changes to shared files -- keep changes as small and isolated as possible." | "Small and isolated" is subjective design judgment. **Current label (intent) is correct.** |
| 61 | behavior_per_event | intent | "Avoid restructuring upstream code -- don't refactor or reorganize code that comes from opencode unless absolutely necessary." | "Unless absolutely necessary" is subjective judgment. This is strategic guidance. Should be intent. |

### langchain-ai/open-swe

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 20 | intent | behavior_per_event | "Built-in deepagents tools... are added by create_deep_agent itself; don't duplicate them." | "Don't duplicate" specific named tools is operationally checkable -- if the agent defines a tool with one of these names, that's a detectable event. However, the primary thrust is informational ("these already exist, don't recreate them"), making intent defensible. **Borderline.** |
| 28 | behavior_cross_object | behavior_per_event | "New sandbox providers: add a module under agent/integrations/ and wire it into SANDBOX_FACTORIES" | This describes where to put new code (file path target). Each step is independently verifiable as a file operation. However, the AND between "add module" + "wire into SANDBOX_FACTORIES" makes it cross_object. **Current label is correct.** |
| 31 | behavior_per_event | intent | "New dashboard endpoints: add to agent/dashboard/routes.py" | This is informational guidance about where to place code. It's a convention pointer, not an enforceable constraint. However, it could be read as "dashboard endpoints MUST go in routes.py" (file path constraint = per_event). **Current label is acceptable.** |

### browser-use/browser-harness

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 2 | intent | -- | "Code priorities: Clarity, Precision, Low verbosity, Versatility" | Correctly classified as intent -- these are subjective design values. |
| 4 | behavior_per_event | -- | "An agent operating the harness only edits inside agent-workspace/" | Correctly classified -- this is a file path constraint checkable per write operation. |

No disagreements found.

### ruvnet/ruflo

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 2 | behavior_per_event | behavior_cross_object | "1. memory_search... 2. swarm_init... 3. YOU write the code... 4. memory_store..." | This is a multi-step workflow with ordering requirements. It's cross_object (must do steps in sequence, memory_search BEFORE task, memory_store AFTER). |
| 54 | behavior_per_event | behavior_cross_object | "memory_search: BEFORE every task / memory_store: AFTER success" | The BEFORE/AFTER temporal constraints make this cross_object (correlating tool usage timing with task lifecycle). |
| 56 | behavior_per_event | behavior_cross_object | "BEFORE starting any task - SEARCH for patterns" | Same -- temporal ordering constraint across operations. |
| 57 | intent | behavior_cross_object | "AFTER completing successfully - STORE the pattern" | The temporal ordering (after completion -> store) is cross_object. Current label as intent underclassifies it. |
| 58 | behavior_per_event | behavior_cross_object | "MCP Learning Workflow: 1. LEARN... 2. COORDINATE... 3. EXECUTE... 4. REMEMBER..." | Multi-step ordered workflow = cross_object. |

### NousResearch/hermes-agent

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 16 | intent | behavior_cross_object | "Adding New Tools: For most custom tools, use the plugin route... Built-in/core tools require changes in 2 files..." | The multi-file coordination requirement (create tools/your_tool.py AND add to toolsets.py) is cross_object. However, the text is largely informational/procedural guidance, and "intent" captures that it's strategic advice about where to put code. The 2-file requirement is a hard constraint though. **Suggest behavior_cross_object.** |
| 37 | behavior_linter | behavior_cross_object | "Prompt Caching Must Not Break... Do NOT implement changes that would alter past context mid-conversation, change toolsets mid-conversation..." | These constraints require tracking state across an entire conversation session -- they're about temporal invariants across multiple operations. This is cross_object. The linter cannot check "did you alter past context mid-conversation" without session-level state. |
| 40 | behavior_per_event | behavior_linter | "Use get_hermes_home() for all HERMES_HOME paths. NEVER hardcode ~/.hermes..." | This requires inspecting code content for hardcoded path strings. That's content inspection = behavior_linter. |
| 41 | behavior_per_event | behavior_linter | "DO NOT hardcode ~/.hermes paths. Use get_hermes_home()..." | Same as above -- code content inspection. behavior_linter. |
| 42 | behavior_per_event | behavior_linter | "DO NOT introduce new simple_term_menu usage" | Checking whether code contains imports/usage of a specific library requires content inspection. behavior_linter. |
| 48 | intent | behavior_cross_object | "Don't wire in dead code without E2E validation" | "Without E2E validation" implies a temporal ordering: validate BEFORE wiring in. This requires cross-object correlation. However, the judgment of what constitutes "dead code" is subjective (intent). **Borderline -- intent is defensible.** |

### rtk-ai/rtk

| ID | Current | Suggested | Text (abbreviated) | Reasoning |
|---|---|---|---|---|
| 4 | behavior_per_event | intent | "If rtk is installed, prefer rtk <cmd> over raw commands for token-optimized output." | "Prefer" is soft guidance about command choice. The conditional ("if installed") adds judgment. This is strategic preference = intent. |
| 8 | behavior_cross_object | -- | "Pre-commit Gate: cargo fmt --all && cargo clippy --all-targets && cargo test --all" | Correctly classified -- multi-step gate before committing. |
| 25 | behavior_per_event | intent | "No async: single-threaded by design" | This is an architectural constraint that requires understanding code patterns (is this async?). It's a design principle. Could be behavior_linter (detecting async usage in code), but the "by design" framing makes it a design principle statement. **Suggest behavior_linter** since checking for async keywords/patterns in Rust code is linter-checkable. |
| 29 | behavior_cross_object | -- | "After ANY Rust file edits, ALWAYS run the full quality check pipeline before committing" | Correctly classified -- temporal ordering across operations. |
| 30 | behavior_cross_object | -- | "Never commit code that hasn't passed all 3 checks" | Correctly classified -- correlating test results with commit action. |
| 31 | behavior_per_event | behavior_cross_object | "Fix ALL clippy warnings before moving on (zero tolerance)" | "Before moving on" implies temporal ordering -- fix warnings before proceeding to next task. This is cross_object. |
| 32 | behavior_per_event | behavior_cross_object | "If build fails, fix it immediately before continuing to next task" | Same pattern -- conditional temporal ordering. Cross_object. |
| 33 | behavior_per_event | behavior_cross_object | "Performance verification (for filter changes): run hyperfine before/after" | Conditional on "filter changes" + requires running benchmarks at specific times. Cross_object. |
| 34 | behavior_per_event | -- | "ALWAYS confirm working directory before starting any work: pwd, git branch" | This is about running specific commands. Each command is a single event. However, "before starting any work" is a temporal constraint making it cross_object. **Suggest behavior_cross_object.** |
| 45 | intent | -- | "Execute sequentially, Commit after each logical step, Never skip or reorder..." | Correctly classified as intent -- these are agent strategy/workflow instructions. |

---

## Systematic Patterns Identified

### 1. Navigation pointers consistently misclassified as behavior_per_event
**Pattern:** "Use skill X", "Refer to file Y", "Read Z before starting" are consistently labeled behavior_per_event when they should be intent.
**Affected repos:** google/adk-python (IDs 2-6, 10), Kilo-Org/kilocode (ID 54), charmbracelet/crush (ID 43).
**Rule reminder:** "Pure navigation pointers ('see X file', 'read X docs') = intent."

### 2. Conditional "if you change X, then do Y" under-classified
**Pattern:** Directives of the form "if you modify file A, run command B" or "when schema changes, regenerate code" are sometimes labeled behavior_per_event when they should be behavior_cross_object (correlating a file change with a subsequent action).
**Affected repos:** openai/codex (IDs 22, 46), vxcontrol/pentagi (ID 15).
**These require tracking state across two operations -- the triggering change and the required follow-up.**

### 3. Code content inspection labeled as behavior_per_event
**Pattern:** Directives about what code must/must not contain (e.g., "never hardcode ~/.hermes", "don't use simple_term_menu", "annotate with kilocode_change markers") are labeled behavior_per_event when they require inspecting file content = behavior_linter.
**Affected repos:** NousResearch/hermes-agent (IDs 40, 41, 42), Kilo-Org/kilocode (IDs 17, 26), openai/codex (IDs 5, 15, 64).

### 4. Temporal ordering constraints ("before/after") under-classified
**Pattern:** "Search memory BEFORE starting", "Store patterns AFTER success", "Fix warnings before moving on" are labeled behavior_per_event but require cross-object temporal correlation.
**Affected repos:** ruvnet/ruflo (IDs 2, 54, 56, 57, 58), rtk-ai/rtk (IDs 31, 32, 33, 34).

### 5. Soft preference language ("prefer", "resist", "when possible") treated as enforceable
**Pattern:** Directives with hedge words are sometimes classified at a higher enforceability level than warranted. "Prefer X over Y" and "resist adding" are subjective judgments closer to intent.
**Affected repos:** rtk-ai/rtk (ID 4), Kilo-Org/kilocode (ID 61).
**However, many "prefer X" style directives are correctly classified as behavior_linter when they describe concrete code patterns. The issue is inconsistency.**

### 6. Multi-step procedural guides under-classified
**Pattern:** "Adding a new provider: 1. Create file in X, 2. Add constant to Y, 3. Register in Z..." are sometimes labeled behavior_per_event when the multi-step correlation requirement makes them behavior_cross_object.
**This pattern is generally handled correctly (e.g., vxcontrol/pentagi ID 14, langchain-ai/open-swe IDs 28-30).**

---

## Summary of Disagreements by Severity

### Strong Disagreements (clear misclassification)
- **google/adk-python IDs 2-6, 10**: Navigation pointers labeled behavior_per_event, should be intent (6 items)
- **openai/codex ID 5**: Code content rule labeled behavior_per_event, should be behavior_linter
- **openai/codex ID 22**: Cross-file coordination labeled behavior_linter, should be behavior_cross_object
- **openai/codex ID 46**: Cross-object (UI change + snapshot test) labeled behavior_linter, should be behavior_cross_object
- **vxcontrol/pentagi ID 15**: "If you change X, run Y" labeled behavior_per_event, should be behavior_cross_object
- **NousResearch/hermes-agent IDs 40, 41, 42**: Code content inspection labeled behavior_per_event, should be behavior_linter
- **NousResearch/hermes-agent ID 37**: Session-level invariant labeled behavior_linter, should be behavior_cross_object
- **Kilo-Org/kilocode ID 17**: Code content annotation requirement labeled behavior_per_event, should be behavior_linter
- **ruvnet/ruflo IDs 2, 54, 56, 58**: Temporal ordering workflows labeled behavior_per_event, should be behavior_cross_object

### Moderate Disagreements (defensible but inconsistent)
- **openai/codex ID 15**: Content-dependent path constraint (per_event vs linter)
- **openai/codex ID 25**: "Be patient" + "never kill" (cross_object vs per_event)
- **openai/codex ID 64**: API surface area judgment (per_event vs linter)
- **openai/codex ID 71**: Same-struct annotation consistency (cross_object vs linter)
- **Kilo-Org/kilocode ID 26**: Setting placement judgment (per_event vs linter)
- **Kilo-Org/kilocode ID 54**: Skill file navigation pointer (linter vs intent)
- **Kilo-Org/kilocode ID 56, 61**: Subjective "last resort" / "unless necessary" (per_event vs intent)
- **rtk-ai/rtk IDs 31, 32, 33, 34**: Temporal ordering (per_event vs cross_object)
- **rtk-ai/rtk ID 4**: "prefer" language (per_event vs intent)
- **rtk-ai/rtk ID 25**: "No async" design principle (per_event vs linter)
- **ruvnet/ruflo ID 57**: "After success, store pattern" (intent vs cross_object)
- **NousResearch/hermes-agent ID 16**: Procedural guide (intent vs cross_object)

---

## Overall Quality Assessment

**Overall quality: Good, with consistent systematic biases.**

The annotations are largely correct for the majority of statements. Descriptions are properly identified and given null enforceability. The directive/description distinction is generally sound. Confidence levels are uniformly high, which seems appropriate for these fairly unambiguous instruction files.

**Estimated error rate:** ~8-12% of directive classifications have a defensible disagreement, with ~5% being clear misclassifications.

**Main systematic issues (in order of frequency):**

1. **Navigation pointers over-classified as behavior_per_event** (~6-8 instances across the sample). This is the single largest systematic error. The rule "Pure navigation pointers = intent" is not being applied consistently.

2. **Code content constraints classified as behavior_per_event instead of behavior_linter** (~6 instances). When a directive requires inspecting what code contains (variable names, import statements, hardcoded strings), that is content inspection, not operation matching.

3. **Temporal ordering ("before/after") under-recognized as cross_object** (~8 instances). When a directive requires correlating the timing of one operation relative to another, that is cross_object even if each individual operation is simple.

4. **Conditional cross-file requirements ("if you change X, update Y") sometimes missed** (~3 instances). These are cross_object by definition.

**The description/null classification is consistently correct** -- no instances of descriptions being given enforceability labels or vice versa.

**Topic classifications appear reasonable** across all reviewed files, with no obvious misassignments noted.
