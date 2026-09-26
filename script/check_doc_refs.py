#!/usr/bin/env python3
"""Fail if a committed doc reference points at a path that does not exist.

Documentation and code comments cite each other by repo-relative path
(`docs/rule-language.md`, `docs/design/feedback-design.md`). When a doc is
renamed, moved, or removed, those citations are not updated by anything, and the
result is a dead pointer a reader follows to nothing. This has happened three
times on this branch:

  * `docs/taint-dsl.md` -> `docs/rule-language.md`, with the e2e case files still
    citing both the old name and a `docs/taint-dsl-v2.md` that never existed
    under that name;
  * `docs/feedback-design.md` -> `docs/design/feedback-design.md`, with four
    citations left behind in two Rust files and one shell-adjacent doc;
  * `docs/reference/oss-landscape.md`, removed from the product branch as
    paper-only material while `docs/design/related_work.md` still cited it.

The check is: every file and directory citation under `docs/` in a committed text
file resolves, or is explicitly qualified as living somewhere else. A reference
is allowed to be absent when the text says where it actually is, which is how this
repo documents material kept on the artifact refs (`artifact-ready`,
`backup/...`) rather than on the product branch. The signal for that is a ref name
in the surrounding text, so the check reads a window before the match rather than
the whole line: prose like "lives on `backup/2026-06-14-master` as
`docs/reference/oss-landscape.md`" is correct and must not fail.

File and directory citations are checked by different rules. A file citation
(`REF`, extension-bearing) must resolve, because a file has one path per branch. A
directory citation is checked only for the moved-deeper case (`DIR_REF` plus
`moved_deeper`): it flags a citation when a tracked directory path ends with it,
while a directory the branch deliberately keeps elsewhere or a generated output
dir passes. That split exists because a directory named in `docs/ARTIFACT.md` may
resolve on a different ref but not on the one being read.

Skipped: the `docs/papers` submodule (a separate repository), vendored trees, and
build output, whose contents are not this repo's to keep in sync.

The first check covers `docs/` paths and repo-relative paths outside `docs/`.
The out-of-`docs/` class was once left out over two false positives, since
neither carries the same failure mode:

  * `#include <bpf/bpf.h>`-style names resolve through `-I` at build time, so
    they are not repo-relative even when the text looks like a path; a line with
    `#include` is skipped;
  * `crates/.../dsl/lower.rs` is a deliberate abbreviation in the docstrings of
    `docs/empirical-study/replay_fp_lowering.py`, not a citation to follow, and
    an ellipsis marks it.
  * `test/fixtures/...` can be relative to a frozen corpus rather than this
    tree; a citation on a line naming the corpus is taken as corpus-relative.

With those excluded, 86 citations over `script/`, `crates/`, `bpf/`, `test/`,
`examples/`, `tools/`, and `.github/` resolve, so the class is checked rather
than assumed clean.

The second check runs the other way: every committed directory under
`docs/empirical-study/results/` must be named in the reviewer-facing index
(`docs/empirical-study/README.md`). Evidence a reader cannot find is evidence that
does not count, and the index had listed three of the eight committed directories
before this was written. The directory set comes from `git ls-files` rather than a
filesystem walk, because this checkout can hold untracked result dirs from other
branches and CI checks out only what is committed; a walk would make the local and
CI verdicts differ.

A third class is checked because it drifted the same way. The skill files under
`.claude/skills/` cite each other by slash-command (`/paper-review`), which names a
skill directory rather than a path, so no path-shaped rule saw it: one skill told
the reader to run `/paper-fix`, and no skill or command by that name exists
anywhere in the tree. The check is scoped to that tree, the only place that cites
commands this way, and requires a hyphenated name, because the prose slashes in
those files (`/sections`, `/figure`) are not commands. A reference is correct when
it names a skill directory that exists.

A fourth class is a symbol citation bound to the file that should define it. The
prose writes `` `test_abi_layout` in `bpf/test_taint.c` `` and
`` `te_after_satisfied` in `taint_engine.bpf.h` `` to point a reader at the
guard for a claim. No
path-shaped rule reads the identifier beside the path, so renaming that function,
or moving the file it lives in, leaves the citation crediting a file that no
longer defines it while every path check stays green. The check binds an
identifier to a file token only when the two sit in one short clause, resolves a
shortened file name by basename against the committed tree, and requires the
identifier to appear in a file named on its line. It also fails when the cited
file itself no longer resolves, since a moved file would otherwise drop the
citation out of the checked set silently.

A fifth class is an environment variable a doc tells the reader to set. The
names are all `ACTPLANE_`-prefixed, so a removed or renamed knob leaves the doc
instructing the reader to set a variable the code no longer reads, and no
path-shaped rule sees it because the name is not a path. The check resolves a
cited name against the committed code and scripts, which is where the reader's
tooling would find it.

A sixth class is a Cargo package name a doc tells the reader to build
(`cargo test -p actplane-runtime`). The name is not a path, so no path check
sees it: renaming a crate under `crates/` leaves every doc naming a package that
no longer exists while the guard stays green. The name resolves when a committed
`Cargo.toml` declares it.

A seventh class is a worked example's label. `docs/rule-language.md` §3 numbers
its examples (`### E13 — ...`) and `test/e2e_cases.yaml` names each live case
with the same label, so a reader can go from a rule to its case. The two drifted
in both directions: the doc grew an `### E13` section (migration freshness) no
case exercised, and the case file grew an `E14` case (negated `unless target`)
the doc never named, while the file's own header claims the two mirror each
other. The check compares the example *base* labels (`E13`) on both sides, so a
sub-label such as `E5b` and an example folded into another case's label
(`E1 (+E8 declassify)`) both resolve to the example they belong to.

Usage: python3 script/check_doc_refs.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Reference to a repo-relative docs path. Extensions we cite this way. `tsv`
# and `js` carry committed evidence (`docs/empirical-study/candidate_rules_144.tsv`,
# `docs/empirical-study/audit_rq2_verdicts.js`), and `.txt` is left out because
# the tree cites it both ways, as a `--report-out` destination
# (`docs/actplane-review.txt`) and as a file joined onto an external
# `ARTIFACT_ROOT`, and neither is a path this branch must contain.
# The trailing lookahead keeps the extension token whole. Without it the greedy
# path prefix backtracks to a shorter listed extension sharing a prefix, so
# `docs/corpus-raw-full/manifest.jsonl` matched as `..../manifest.json` and was
# reported as a missing file, and no `.jsonl` citation could ever resolve.
REF = re.compile(
    r"docs/[A-Za-z0-9_./-]+\.(?:md|yaml|yml|jsonl|json|tsv|js|sh|py|rs|c|h|toml)(?![A-Za-z0-9])"
)

# A citation to a repo-relative path outside `docs/`. `REF` anchors on `docs/`,
# so a doc that names `script/check_prebuilt_fresh.sh` or `bpf/process.bpf.c`
# went unchecked while the file was free to move. The docstring records why this
# class was left out; it is checked now because the two false positives it named
# are cheaply excluded: an `#include <bpf/bpf.h>` resolves through the compiler's
# `-I`, so a line with `#include` is skipped, and the ellipsis form
# `crates/.../dsl/lower.rs` is a deliberate abbreviation, not a path. The
# extension list mirrors `REF`; the lookahead keeps the extension token whole.
NON_DOC_REF = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?:script|crates|bpf|test|examples|tools|\.github)/"
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*"
    r"\.(?:md|yaml|yml|jsonl|json|tsv|js|sh|py|rs|c|h|toml|txt)(?![A-Za-z0-9])"
)

# A `test/fixtures/...` citation can be relative to a frozen corpus rather than
# this tree: `docs/empirical-study/rq2-lowering-eval.md` quotes the observed
# event `test/fixtures/src-lib-new-command.js.txt` from the NemoClaw run, a path
# that only exists in that corpus. Such a line names the corpus, so the check
# takes the name as the qualifier that says "not this tree".
NON_DOC_QUALIFIERS = ("NemoClaw",)

# Text files whose citations we check.
SUFFIXES = (".md", ".rs", ".sh", ".yaml", ".yml", ".c", ".h", ".toml", ".py", ".js")

# Trees that belong to something else (separate repo, vendored, or generated).
SKIP_PREFIXES = ("docs/papers/", "libbpf/", "bpftool/", "target/", "bpf/.output/")

# This checker is excluded because its docstring enumerates the dead references it
# exists to catch, so it names paths that do not exist by design. That is the one
# file where a missing path is the point rather than a defect; excluding the file
# is narrower than weakening the rule for the rest of the tree.
SELF = "script/check_doc_refs.py"

# A reference is allowed to be absent when the surrounding text says which ref
# holds it, which is how this repo documents material deliberately kept off the
# product branch (see docs/ARTIFACT.md). The window covers the whole line and a
# little of either side, so a qualifier placed before ("lives on
# backup/2026-06-14-master as `docs/reference/oss-landscape.md`") or after
# ("matching `docs/artifact/verify_results.py` on the artifact ref") the path both
# count. A tighter window before the match rejected the second form.
REF_QUALIFIERS = (
    "artifact-ready",
    "artifact ref",
    "backup/",
    "origin/artifact",
    "renamed from",
    "moved to",
    "moved off",
    "lives on",
    "no longer exists",
    "removed from",
)
WINDOW = 240

# A directory citation. `REF` requires a file extension, so the four citations to
# `docs/rq2-performance/` in `docs/ARTIFACT.md` went unchecked while that directory
# gained a `design/` segment, and the guard reported green. Checking every
# directory citation directly would flag the many refs that name a directory the
# branch deliberately keeps elsewhere (`docs/corpus-test/`, `docs/eval_runs/`,
# `docs/artifact/`), so the check is narrower: flag a directory ref only when a
# tracked directory path *ends with* it, which is the signature of a directory
# that moved deeper while the citation kept the old head. A ref that resolves,
# names a generated output dir (`results/`, `tmp/`), or points at another branch
# matches nothing and passes.
DIR_REF = re.compile(r"docs/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/")

# A citation that climbs the tree, such as `../../test/policies/` from a crate
# README. `REF` anchors on `docs/`, so every relative citation went unchecked;
# `crates/actplane-cli/README.md` had two that were one level short (its own
# `../actplane-ifc-compiler/` anchor shows the base is the citing file's
# directory, not the repo root). Resolve each against the citing file's
# directory rather than the root, which is what a reader's tooling does.
# The extension list and trailing lookahead mirror `REF`; without them a
# `../../x.jsonl` citation matched as `../../x.json` and failed naming a path
# that exists nowhere, the same prefix-backtracking defect.
UP_REF = re.compile(
    r"(?<![A-Za-z0-9_./-])(?:\.\./)+"
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*"
    r"\.(?:md|yaml|yml|jsonl|json|tsv|js|sh|py|rs|c|h|toml)(?![A-Za-z0-9])"
)

# A slash-command citation inside a skill file, such as `/paper-review`. Skills
# cross-reference each other by command name, and `.claude/skills/paper-logic/
# SKILL.md` told the reader to run `/paper-fix`, which names no skill and no
# command anywhere in the tree, while the guard stayed green. Requiring a
# hyphenated name keeps prose slashes (`/sections`, `/figure`) out of the check
# (all three real command names are hyphenated), and the check is scoped to the
# skills tree, the one place that cites commands this way. A backtick may precede
# the command, which is how the drifted reference was written.
SLASH_CMD = re.compile(r"(?<![A-Za-z0-9_./-])/[a-z][a-z0-9]*(?:-[a-z0-9]+)+")
SKILLS_DIR = ".claude/skills/"

# A symbol citation bound to the file that should define it: `` `sym` in
# `file.rs` `` (or any wording where the two sit within one short clause).
# `REF`/`DIR_REF`/`UP_REF` only check that a *path* exists; none of them looks at
# the identifier beside it. The compiler, the skill, and `bpf/README.md` all
# write the test that pins an ABI field as `` `test_abi_layout` in
# `bpf/test_taint.c` ``, and a rename of that function or a move to another file
# would leave the citation pointing at a file that no longer defines it while
# every existing check stayed green (the file still exists, so `REF` passes).
# The check is deliberately narrow:
#   * the identifier must be adjacent to a file token, so a line that names a
#     source file and, elsewhere, an unrelated symbol is not bound to it (this
#     is what keeps `std::slice::from_raw_parts` beside `taint.h` from being
#     read as a `taint.h` symbol);
#   * the file name is resolved to committed `.rs`/`.c`/`.h` files by basename,
#     so the docs' shortened forms (`lower.rs`, `taint_engine.bpf.h`) work
#     without a full path;
SYM_SOURCE_SUFFIXES = (".rs", ".c", ".h")
SYM_BOUND = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]*)`[^`\n]{0,40}?`([A-Za-z0-9_./-]+\.(?:rs|c|h))`"
)
SYM_TOKEN = re.compile(r"`([^`\n]+)`")

# An `ACTPLANE_`-prefixed environment variable a doc instructs the reader to
# set. The name is not a path, so no other check sees it: a renamed or removed
# knob leaves the doc telling the reader to set a variable the code no longer
# reads while every path check stays green. The name resolves when the same
# name appears in a committed non-doc file (code or script), which is where the
# reader's tooling finds it; a name only ever written in a doc does not define
# itself, which is the failure this catches.
ENV_REF = re.compile(r"\bACTPLANE_[A-Z0-9_]+\b")

# A `cargo <cmd> -p <name>` citation. The name is a Cargo package, not a path, so
# no path check reads it: renaming a crate under `crates/` leaves every doc
# telling the reader to build a package that no longer exists while the guard
# stays green. The name resolves when a committed `Cargo.toml` declares it. The
# value is matched after a bare `-p`, which is how the docs spell the flag (not
# `--package`), and only on a line that names `cargo`, so the many other `-p`
# flags (`actplane run -p`) are not read as packages.
PKG_REF = re.compile(r"(?<![A-Za-z0-9_-])-p\s+([A-Za-z_][A-Za-z0-9_-]*)")

# A worked-example label. `docs/rule-language.md` §3 numbers its examples in
# `### E<n>` headings and `test/e2e_cases.yaml` labels each live case with the
# same token, which is how a reader goes from a rule to the case that enforces
# it. The two are compared as sets, in both directions, on the base form
# (`E13`), because a case may carry a sub-label (`E5b`) or fold in a second
# example (`E1 ... (+E8 declassify)`).
E_EXAMPLE_DOC = "docs/rule-language.md"
E_EXAMPLE_CASES = "test/e2e_cases.yaml"
E_HEADING = re.compile(r"^### (E\d+)\b", re.M)
E_LABEL = re.compile(r"\b(E\d+)[a-z]?\b")


def tracked_dirs(files: list[str]) -> set[str]:
    """Every directory path in the committed tree, with a trailing slash."""
    dirs: set[str] = set()
    for name in files:
        for parent in Path(name).parents:
            if str(parent) != ".":
                dirs.add(str(parent) + "/")
    return dirs


def source_files(files: list[str]) -> tuple[set[str], dict[str, list[str]]]:
    """Committed source files, and the same keyed by basename.

    Docs shorten a path (`lower.rs` for the only `lower.rs`), so a citation is
    resolved against the exact committed path first and then by basename. The
    committed list is the authority, so a file that exists only in a stale
    checkout cannot satisfy a citation.
    """
    exact = {n for n in files if n.endswith(SYM_SOURCE_SUFFIXES)}
    by_base: dict[str, list[str]] = {}
    for n in exact:
        by_base.setdefault(Path(n).name, []).append(n)
    return exact, by_base


def bound_sources(
    names: list[str], exact: set[str], by_base: dict[str, list[str]]
) -> list[str]:
    """The committed source files a line's file tokens name, in stable order."""
    out: list[str] = []
    for n in names:
        if n in exact:
            out.append(n)
        else:
            out.extend(by_base.get(Path(n).name, []))
    return sorted(set(out))


def moved_deeper(ref: str, dirs: set[str]) -> bool:
    """True when a tracked directory path ends with `ref` minus its `docs/` head.

    `docs/rq2-performance/` is shadowed by `docs/design/rq2-performance/`, so the
    citation kept the pre-move head. The trailing-slash form keeps this from
    matching a directory that merely shares a name prefix.
    """
    tail = "/" + ref[len("docs/") :]
    return any(d.endswith(tail) and d != "docs/" + ref[len("docs/") :] for d in dirs)

# The reviewer-facing index for the retained evidence, and the tree it indexes.
# Every committed directory under RESULTS_DIR must be named in INDEX, so a reader
# can find evidence that the product branch retains.
RESULTS_DIR = "docs/empirical-study/results"
INDEX = "docs/empirical-study/README.md"

def committed_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    problems: list[tuple[str, str]] = []
    sym_problems: list[tuple[str, str]] = []
    env_problems: list[tuple[str, str]] = []
    pkg_problems: list[tuple[str, str]] = []
    e2e_problems: list[tuple[str, str]] = []
    # Per-class tallies, so a regex that stops matching a whole class of
    # citations fails the run instead of silently shrinking what is checked.
    checked = 0
    by_class = {
        "file": 0,
        "dir": 0,
        "up": 0,
        "slash_cmd": 0,
        "symbol": 0,
        "env": 0,
        "non_doc": 0,
        "pkg": 0,
        "example": 0,
    }

    files = committed_files()
    for name in files:
        if name.endswith("/") or not name.endswith(SUFFIXES):
            continue
        if name.startswith(SKIP_PREFIXES) or name == SELF:
            continue
        path = root / name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for match in REF.finditer(text):
            ref = match.group(0).rstrip(".,);`'\"")
            checked += 1
            by_class["file"] += 1
            if (root / ref).exists():
                continue
            # A qualifier may precede or follow the path, so read both sides.
            window = text[max(0, match.start() - WINDOW) : match.end() + WINDOW]
            if any(q in window for q in REF_QUALIFIERS):
                continue
            line = text.count("\n", 0, match.start()) + 1
            problems.append((f"{name}:{line}", ref))

    # Citations to repo-relative paths outside `docs/` (see `NON_DOC_REF`). The
    # citing set is the committed `.md` files, where a reader follows a path; the
    # code comments that also cite paths are not instructions a reader acts on.
    # The qualifier window and the line-level exclusions mirror the `REF` check,
    # so a citation the text says lives on another ref still passes.
    for name in files:
        if not name.endswith(".md") or name.startswith(SKIP_PREFIXES):
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in NON_DOC_REF.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line = text[line_start : line_end if line_end != -1 else len(text)]
            if "#include" in line or "..." in line:
                continue
            ref = match.group(0)
            checked += 1
            by_class["non_doc"] += 1
            if (root / ref).exists():
                continue
            # A qualifier may precede or follow the path, so read both sides.
            window = text[max(0, match.start() - WINDOW) : match.end() + WINDOW]
            if any(q in window for q in REF_QUALIFIERS + NON_DOC_QUALIFIERS):
                continue
            line_no = text.count("\n", 0, match.start()) + 1
            problems.append((f"{name}:{line_no}", ref))

    # Directory citations, checked separately because `REF` needs a file
    # extension and so never sees them (see `DIR_REF`).
    dirs = tracked_dirs(files)
    for name in files:
        if name.endswith("/") or not name.endswith(SUFFIXES):
            continue
        if name.startswith(SKIP_PREFIXES) or name == SELF:
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in DIR_REF.finditer(text):
            end = match.end()
            if end < len(text) and text[end] == "*":
                continue  # a glob such as `docs/corpus-test/*/*/rule.yaml`
            start = match.start()
            while start > 0 and not text[start - 1].isspace():
                start -= 1
            if "://" in text[start : match.start()]:
                continue  # a URL such as `https://tetragon.io/docs/.../selectors/`
            ref = match.group(0)
            checked += 1
            by_class["dir"] += 1
            if (root / ref).exists():
                continue
            if not moved_deeper(ref, dirs):
                continue
            window = text[max(0, match.start() - WINDOW) : end + WINDOW]
            if any(q in window for q in REF_QUALIFIERS):
                continue
            line = text.count("\n", 0, match.start()) + 1
            problems.append((f"{name}:{line}", ref))

    # Tree-climbing citations (`../...`), checked relative to the citing file's
    # own directory. `REF` and `DIR_REF` both anchor on `docs/`, so a relative
    # citation was invisible to the guard; two in `crates/actplane-cli/README.md`
    # had drifted one level short while the guard reported green.
    for name in files:
        if name.endswith("/") or not name.endswith(SUFFIXES):
            continue
        if name.startswith(SKIP_PREFIXES) or name == SELF:
            continue
        base = (root / name).parent
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in UP_REF.finditer(text):
            ref = match.group(0).rstrip(".,);`'\"")
            checked += 1
            by_class["up"] += 1
            if (base / ref).resolve().exists():
                continue
            window = text[max(0, match.start() - WINDOW) : match.end() + WINDOW]
            if any(q in window for q in REF_QUALIFIERS):
                continue
            line = text.count("\n", 0, match.start()) + 1
            problems.append((f"{name}:{line}", ref))

    # Slash-command citations in the skills tree (`/paper-review`). These name a
    # skill by its directory rather than a path, so `REF` never sees them: a
    # reference to `/paper-fix` resolved to no skill and the guard still passed.
    # A command typo'd without its hyphen is prose and stays unchecked; this
    # catches the shape that actually drifted.
    skills = {
        Path(n).parts[2]
        for n in files
        if n.startswith(SKILLS_DIR) and len(Path(n).parts) > 2
    }
    for name in files:
        if not name.startswith(SKILLS_DIR) or not name.endswith(SUFFIXES):
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in SLASH_CMD.finditer(text):
            command = match.group(0)[1:]
            checked += 1
            by_class["slash_cmd"] += 1
            if command in skills:
                continue
            line = text.count("\n", 0, match.start()) + 1
            problems.append((f"{name}:{line}", match.group(0)))

    # A symbol citation bound to its defining file (see `SYM_BOUND`). The file
    # token must resolve to committed source, and the identifier must appear in
    # one of the file(s) named on its line.
    src_exact, src_by_base = source_files(files)
    src_text: dict[str, str] = {}
    for name in files:
        if name in src_exact:
            try:
                src_text[name] = (root / name).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                pass
    for name in files:
        if name.endswith("/") or not name.endswith(SUFFIXES):
            continue
        if name.startswith(SKIP_PREFIXES) or name == SELF:
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            line_tokens = [
                m.group(1)
                for m in SYM_TOKEN.finditer(line)
                if m.group(1).endswith(SYM_SOURCE_SUFFIXES)
            ]
            targets = bound_sources(line_tokens, src_exact, src_by_base)
            blob = "\n".join(src_text.get(t, "") for t in targets)
            for m in SYM_BOUND.finditer(line):
                symbol, cited = m.group(1), m.group(2)
                checked += 1
                by_class["symbol"] += 1
                where = f"{name}:{line_no}"
                # The cited file must still resolve. A moved file otherwise drops
                # the citation out of the checked set silently: `REF` only tests
                # the token as written, and the moved file makes this one
                # unresolvable, so the symbol would never be looked for.
                if not bound_sources([cited], src_exact, src_by_base):
                    sym_problems.append((where, f"`{cited}` (cited for `{symbol}`)"))
                elif not re.search(r"\b" + re.escape(symbol) + r"\b", blob):
                    sym_problems.append((where, f"`{symbol}` in {cited}"))

    # A documented `ACTPLANE_`-prefixed env var (see `ENV_REF`). The name
    # resolves when a committed non-doc file names it, so a renamed or removed
    # knob fails here while the doc still tells the reader to set it. The
    # definition set is built from `files`, so the committed tree decides, not a
    # stale checkout. A `.sh` under `docs/` counts as a definition: the VM
    # harness scripts live there and are what a reader would run.
    env_defined: set[str] = set()
    for name in files:
        if name.endswith("/") or name.endswith(".md") or name.startswith(SKIP_PREFIXES):
            continue
        try:
            env_defined.update(
                ENV_REF.findall(
                    (root / name).read_text(encoding="utf-8", errors="replace")
                )
            )
        except OSError:
            continue
    # The citing set is every committed `.md`, not only `docs/`: the top-level
    # and crate READMEs and the skills also tell a reader to export these names,
    # so scoping to `docs/` would leave those instructions unguarded.
    for name in files:
        if name.endswith("/") or not name.endswith(".md"):
            continue
        if name.startswith(SKIP_PREFIXES) or name == SELF:
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for m in ENV_REF.finditer(line):
                checked += 1
                by_class["env"] += 1
                if m.group(0) not in env_defined:
                    env_problems.append((f"{name}:{line_no}", m.group(0)))

    # A documented `cargo <cmd> -p <name>` citation (see `PKG_REF`). The
    # declared packages come from the committed `Cargo.toml` files, so renaming
    # a crate fails here while every doc still names the old package.
    pkg_defined: set[str] = set()
    for name in files:
        if name.endswith("/") or not name.endswith("Cargo.toml"):
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_package = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_package = stripped == "[package]"
                continue
            if in_package:
                m = re.match(r'name\s*=\s*"([^"]+)"', stripped)
                if m:
                    pkg_defined.add(m.group(1))
                    in_package = False
    for name in files:
        if name.endswith("/") or not name.endswith(".md"):
            continue
        if name.startswith(SKIP_PREFIXES) or name == SELF:
            continue
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if "cargo" not in line:
                continue
            for m in PKG_REF.finditer(line):
                checked += 1
                by_class["pkg"] += 1
                if m.group(1) not in pkg_defined:
                    pkg_problems.append((f"{name}:{line_no}", m.group(1)))

    # Worked-example labels (see `E_HEADING`/`E_LABEL`). The doc's `### E<n>`
    # headings and the case file's `- name: "E<n> ..."` labels are one set a
    # reader crosses between, and they had drifted apart in both directions.
    # The comparison is on the base label, so a case sub-label (`E5b`) and an
    # example folded into another case's label (`E1 ... (+E8 declassify)`) each
    # resolve to their example. Both sides come from committed files, and both
    # are cited, so the class is counted per label rather than per side.
    doc_path = root / E_EXAMPLE_DOC
    cases_path = root / E_EXAMPLE_CASES
    if doc_path.is_file() and cases_path.is_file():
        doc_labels = set(
            E_HEADING.findall(
                doc_path.read_text(encoding="utf-8", errors="replace")
            )
        )
        case_labels: set[str] = set()
        for m in re.finditer(
            r'^  - name:\s*"([^"]*)"',
            cases_path.read_text(encoding="utf-8", errors="replace"),
            re.M,
        ):
            case_labels.update(E_LABEL.findall(m.group(1)))
        for label in sorted(doc_labels | case_labels):
            checked += 1
            by_class["example"] += 1
            if label in doc_labels and label not in case_labels:
                e2e_problems.append(
                    (E_EXAMPLE_DOC, f"### {label} has no case in {E_EXAMPLE_CASES}")
                )
            elif label in case_labels and label not in doc_labels:
                e2e_problems.append(
                    (E_EXAMPLE_CASES, f"{label} has no ### {label} in {E_EXAMPLE_DOC}")
                )

    # Reverse direction: a committed evidence directory that no doc names is
    # evidence a reader cannot find. The results tree had eight committed
    # directories while its index listed three, so this is checked rather than
    # assumed. `INDEX` is the reviewer-facing index.
    #
    # The directory list comes from `git ls-files`, not from walking the
    # filesystem: the working tree can hold untracked evidence (this checkout has
    # gitignored `oas-*` result dirs from another branch), and CI checks out only
    # what is committed. Using the tracked set keeps the local and CI verdicts
    # identical, which a filesystem walk would not.
    unindexed = []
    tracked = files
    index_path = root / INDEX
    index_text = (
        index_path.read_text(encoding="utf-8", errors="replace")
        if index_path.is_file()
        else ""
    )
    prefix = RESULTS_DIR + "/"
    result_dirs = set()
    for name in tracked:
        if not name.startswith(prefix):
            continue
        rest = name[len(prefix) :]
        if "/" in rest:  # a file at the top level of results/ has no dir
            result_dirs.add(rest.split("/", 1)[0])
    # The index lives inside `docs/empirical-study/`, so it names directories as
    # `results/<dir>/`; a doc elsewhere would use the full `docs/...` path. Accept
    # either, since both point a reader at the same place.
    for entry in sorted(result_dirs):
        if not (
            f"{RESULTS_DIR}/{entry}/" in index_text
            or f"results/{entry}/" in index_text
        ):
            unindexed.append(f"{RESULTS_DIR}/{entry}/")

    if (
        problems
        or unindexed
        or sym_problems
        or env_problems
        or pkg_problems
        or e2e_problems
    ):
        for where, ref in problems:
            print(f"{where}: {ref} does not exist", file=sys.stderr)
        for where, ref in sym_problems:
            print(f"{where}: no definition of {ref}", file=sys.stderr)
        for where, ref in env_problems:
            print(f"{where}: no code reads {ref}", file=sys.stderr)
        for where, ref in pkg_problems:
            print(f"{where}: no crate declares {ref}", file=sys.stderr)
        for where, ref in e2e_problems:
            print(f"{where}: {ref}", file=sys.stderr)
        for ref in unindexed:
            print(f"{ref}: committed evidence dir is not named in {INDEX}", file=sys.stderr)
        if problems:
            print(
                f"\n{len(problems)} doc reference(s) point at a path that is not in the "
                "tree. Update the citation to the path's current location, or, if it "
                "lives on another ref, name that ref in the surrounding text so the "
                "reader is told where it is.",
                file=sys.stderr,
            )
        if sym_problems:
            print(
                f"\n{len(sym_problems)} doc citation(s) name a symbol the cited file "
                "no longer defines. Point the citation at the file that now defines "
                "the symbol, or update the name it uses.",
                file=sys.stderr,
            )
        if env_problems:
            print(
                f"\n{len(env_problems)} doc citation(s) tell the reader to set an "
                "environment variable no committed code reads. Update the name to the "
                "one the code uses, or drop the instruction if the knob is gone.",
                file=sys.stderr,
            )
        if pkg_problems:
            print(
                f"\n{len(pkg_problems)} doc citation(s) tell the reader to build a "
                "cargo package no `Cargo.toml` declares. Update the name to the crate "
                "that exists, or drop the instruction if the package was removed.",
                file=sys.stderr,
            )
        if e2e_problems:
            print(
                f"\n{len(e2e_problems)} worked example(s) are unmatched between "
                f"{E_EXAMPLE_DOC} §3 and {E_EXAMPLE_CASES}. Add the missing worked "
                "example to the doc, or the missing live case to the case file, so a "
                "reader can reach the case for every rule and the case set stays "
                "covered by the spec.",
                file=sys.stderr,
            )
        if unindexed:
            print(
                f"\n{len(unindexed)} committed evidence dir(s) are missing from "
                f"{INDEX}. Add them, so the index a reader uses to find the evidence "
                "stays complete as directories are added.",
                file=sys.stderr,
            )
        return 1

    # A floor per class: a regex change that stops matching one class of
    # citation would otherwise print "ok" over a silently smaller population.
    floors = {
        "file": 80,
        "dir": 100,
        "up": 10,
        "slash_cmd": 4,
        "symbol": 12,
        # 22 documented env citations measured across the READMEs, skills, and
        # docs; a floor just below catches a pattern that stops matching the
        # class without pinning the exact count.
        "env": 18,
        # 85 md citations to paths outside `docs/` (script/, crates/, bpf/,
        # test/, .github/) measured; a floor just below catches a pattern that
        # stops matching the class.
        "non_doc": 70,
        # 20 documented `cargo -p` citations measured across the READMEs, the
        # skills, and the docs; a floor just below catches a pattern that stops
        # matching the class.
        "pkg": 15,
        # 14 worked-example labels measured in `docs/rule-language.md` §3 and
        # `test/e2e_cases.yaml` (E1..E14, counted once per label across both
        # sides); a floor just below catches a pattern that stops matching the
        # class.
        "example": 10,
    }
    thin = {k: (by_class[k], floors[k]) for k in floors if by_class[k] < floors[k]}
    if thin:
        for k, (got, want) in sorted(thin.items()):
            print(
                f"only {got} {k} citation(s) checked, expected at least {want}: "
                f"has the {k} pattern stopped matching?",
                file=sys.stderr,
            )
        return 1

    print(f"ok   doc references resolve ({checked} checked); evidence dirs indexed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
