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

Scope is `docs/` paths only, and that was checked rather than assumed. The other
path classes a citation could name do not carry the same failure mode:

  * `#include <bpf/bpf.h>`-style names resolve through `-I` at build time, so
    they are not repo-relative even when the text looks like a path;
  * `crates/.../dsl/lower.rs` is a deliberate abbreviation in one docstring, not
    a citation to follow.

A scan for the same class over `script/`, `test/`, `bpf/`, and `crates/` found
only those two false positives, so widening the pattern would add noise without
catching real staleness. `docs/` is where the citations are meant to be followed.

The second check runs the other way: every committed directory under
`docs/empirical-study/results/` must be named in the reviewer-facing index
(`docs/empirical-study/README.md`). Evidence a reader cannot find is evidence that
does not count, and the index had listed three of the eight committed directories
before this was written. The directory set comes from `git ls-files` rather than a
filesystem walk, because this checkout can hold untracked result dirs from other
branches and CI checks out only what is committed; a walk would make the local and
CI verdicts differ.

Usage: python3 script/check_doc_refs.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Reference to a repo-relative docs path. Extensions we cite this way.
REF = re.compile(r"docs/[A-Za-z0-9_./-]+\.(?:md|yaml|yml|json|sh|py|rs|c|h|toml)")

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
UP_REF = re.compile(
    r"(?<![A-Za-z0-9_./-])(?:\.\./)+"
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*"
    r"\.(?:md|yaml|yml|json|sh|py|rs|c|h|toml)"
)


def tracked_dirs(files: list[str]) -> set[str]:
    """Every directory path in the committed tree, with a trailing slash."""
    dirs: set[str] = set()
    for name in files:
        for parent in Path(name).parents:
            if str(parent) != ".":
                dirs.add(str(parent) + "/")
    return dirs


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
    checked = 0

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
            if (root / ref).exists():
                continue
            # A qualifier may precede or follow the path, so read both sides.
            window = text[max(0, match.start() - WINDOW) : match.end() + WINDOW]
            if any(q in window for q in REF_QUALIFIERS):
                continue
            line = text.count("\n", 0, match.start()) + 1
            problems.append((f"{name}:{line}", ref))

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
            if (base / ref).resolve().exists():
                continue
            window = text[max(0, match.start() - WINDOW) : match.end() + WINDOW]
            if any(q in window for q in REF_QUALIFIERS):
                continue
            line = text.count("\n", 0, match.start()) + 1
            problems.append((f"{name}:{line}", ref))

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

    if problems or unindexed:
        for where, ref in problems:
            print(f"{where}: {ref} does not exist", file=sys.stderr)
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
        if unindexed:
            print(
                f"\n{len(unindexed)} committed evidence dir(s) are missing from "
                f"{INDEX}. Add them, so the index a reader uses to find the evidence "
                "stays complete as directories are added.",
                file=sys.stderr,
            )
        return 1

    print(f"ok   doc references resolve ({checked} checked); evidence dirs indexed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
