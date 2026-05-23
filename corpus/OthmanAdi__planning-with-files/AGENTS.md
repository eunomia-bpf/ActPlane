# AGENTS.md — planning-with-files agent reference card

This file is the canonical, session-portable reference for how every agent working in this repo must handle commits, releases, version bumps, CHANGELOG entries, and issue/PR communication.

---

## Commit rules

- **Author**: OthmanAdi only. NEVER add `Co-Authored-By:` trailers.
- **Format**: Conventional Commits — `fix:`, `feat:`, `release:`, `docs:` prefixes.
- **One squashed commit per release or PR merge.**
- No `--no-verify`. No force push to master except tag ref updates.
- Contributors are credited in CHANGELOG `### Thanks` and `CONTRIBUTORS.md`, never in commit trailers.

---

## Release checklist (12 steps)

1. `gh issue view N` and `gh pr view N` — read both in full.
2. Verify the bug is real: find the exact file/line, grep for the pattern, confirm reporter is correct.
3. `python -m pytest tests/ -q` — all tests pass before touching anything.
4. Squash merge: `git fetch origin branch && git merge --squash origin/branch`, then a single commit as OthmanAdi.
5. CHANGELOG — new version entry at top, `### Fixed`/`### Added`/`### Changed`, sachlich, no em-dashes.
6. CONTRIBUTORS.md — add reporter/contributor, bump "Total Contributors: N+", update "Last updated" date.
7. Version bump across all 19 files (see table below).
8. README — update version badge and add row to releases table.
9. `git commit`, `git tag vX.Y.Z`, `git push origin master`, `git push origin vX.Y.Z`.
10. `gh release create vX.Y.Z --title "vX.Y.Z - <short description>" --notes "<release notes>"`.
11. Post comment on PR and/or issue via `gh issue comment N --body "..."` (run through /humanizer first).
12. `gh issue close N` if applicable.

---

## Version bump scope

All 19 files must be bumped to the same version string every release.

| File | Notes |
|------|-------|
| `skills/planning-with-files/SKILL.md` | Primary English |
| `skills/planning-with-files-ar/SKILL.md` | Arabic |
| `skills/planning-with-files-de/SKILL.md` | German |
| `skills/planning-with-files-es/SKILL.md` | Spanish |
| `skills/planning-with-files-zh/SKILL.md` | Simplified Chinese |
| `skills/planning-with-files-zht/SKILL.md` | Traditional Chinese |
| `.codebuddy/skills/planning-with-files/SKILL.md` | CodeBuddy IDE |
| `.codex/skills/planning-with-files/SKILL.md` | Codex IDE |
| `.cursor/skills/planning-with-files/SKILL.md` | Cursor IDE |
| `.factory/skills/planning-with-files/SKILL.md` | Factory IDE |
| `.hermes/skills/planning-with-files/SKILL.md` | Hermes adapter |
| `.kiro/skills/planning-with-files/SKILL.md` | Kiro IDE |
| `.mastracode/skills/planning-with-files/SKILL.md` | Mastra Code |
| `.opencode/skills/planning-with-files/SKILL.md` | OpenCode IDE |
| `.pi/skills/planning-with-files/SKILL.md` | Pi IDE |
| `clawhub-upload/SKILL.md` | ClawHub marketplace upload |
| `.claude-plugin/plugin.json` | Plugin manifest |
| `.claude-plugin/marketplace.json` | Marketplace metadata |
| `CITATION.cff` | Citation file |

**NOT bumped automatically**: `.continue/`, `.gemini/` — intentionally behind. Do not bump without an explicit scope decision.

---

## CHANGELOG format

```
## [X.Y.Z] - YYYY-MM-DD

### Fixed
- Short description of what was wrong and how it was fixed.

### Thanks
- @handle — what they contributed (issue #N / PR #N)
```

Rules:
- Sachlich (matter-of-fact). No em-dashes. No hype.
- Contributor line: first name or @handle, one sentence, issue/PR reference.
- Run any prose through /humanizer before publishing anywhere public.

---

## CONTRIBUTORS.md format

```markdown
### Other Contributors

**[Name](https://github.com/handle)** — [PR #N](link) / [Issue #N](link)
- What they did (one bullet per contribution)
- Impact or context
```

- Update "Total Contributors: N+" count.
- Update "Last updated: YYYY-MM-DD" date.
- Scope determines section: "Other Contributors" for single-issue fix, "Major Contributions" for larger work.

---

## Issue/PR comment style

After a fix ships, comment on the issue or PR:

- Address by `@handle`.
- One sentence: fix confirmed in vX.Y.Z.
- Specific: what the root cause was, what mechanism changed.
- If they are now in CONTRIBUTORS.md, say so.
- Run through /humanizer before posting.

NOT acceptable in any public comment:
- "Great report!"
- "Thank you so much!"
- Em-dashes (do not use — this style)
- "I'd like to"
- Performative warmth of any kind

---

## Release notes format (gh release create --notes)

```
What changed:

- <Bug description> — <what the fix does>
- <Feature description> — <how it works>

Thanks: @handle for reporting issue #N.
```

- Start with what changed, not who did it.
- No em-dashes.
- Thanks at the bottom.

---

## ClawHub distribution

- ClawHub does NOT auto-sync with GitHub.
- After every release: manually upload `clawhub-upload/SKILL.md` at clawhub.io.
- SSL cert on clawhub.io may be expired — proceed through the browser warning.
- skills.sh / `npx skills`: pulls from GitHub master automatically on next crawl.
- Anthropic plugin marketplace: requires ClawHub upload to reflect the new version.

---

## Quick reference: what NOT to do

- Do not add Co-Authored-By to any commit.
- Do not bump .continue or .gemini without explicit instruction.
- Do not edit `task_plan.md` or `DESIGN.md` directly (user-owned contracts).
- Do not log subagent returns into `task_plan.md` — use `progress.md`.
- Do not use em-dashes in any user-facing prose.
- Do not skip ClawHub upload after a release.
