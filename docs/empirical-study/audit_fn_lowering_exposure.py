#!/usr/bin/env python3
"""Static exposure of the repo-relative `**/dir/**` lowering in the frozen RQ2
false-negative set.

`rq2-lowering-eval.md` proves, live, that the compiler lowers a repo-relative
`**/dir/**` pattern to `CONTAINS("/dir/")`, which cannot match a
first-segment-relative path such as `dist/x.js` or `src/functions/a.ts` (the
literal needs a slash before the segment). A *source* with that shape therefore
fails to label a relative read, and any rule that depends on the label stays
silent.

This script asks the bounded follow-up question: among the 28 ActPlane false
negatives in the frozen RQ2 artifact, how many use such a pattern in their frozen
rule AND show a first-segment-relative path for an action of the matching
operation in the recorded tool log, i.e. are *exposed* to the defect?

The audit is role-aware: a `file` pattern in a `source` is materialized on any
successful open (read or write), while a `file` pattern in a rule target is a
sink that only matches its own op. It is static exposure analysis over the frozen
records. It does not observe what path string the frozen kernel actually matched
(the artifact does not retain per-task kernel logs), and it cannot see paths
written *inside* a script executed via Bash, so it identifies candidates
consistent with the defect, not proven causation.

Inputs (all read-only):
  --corpus  extracted `docs/corpus-test` (frozen rule.yaml files)
  --artifact extracted `docs/artifact/rq2-qwen-primary` (runner results)
  --rows    JSON rows array from `audit_rq2_verdicts.js`
"""

from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
from pathlib import Path

# Reuse the validated matcher/lowering port from the companion replay script.
_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("replay_fp_lowering", _HERE / "replay_fp_lowering.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


# Each recorded tool maps to the kernel op it produces. Only a `read`-op rule can
# be missed by a file *source* (which matches on read/open), and only a
# `write`-op rule by a write sink; conflating them produces false candidates.
TOOL_OP_READ = {"Read", "Grep", "Glob"}
TOOL_OP_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def action_paths(result: dict) -> list[dict]:
    """Recorded actions as {"tool", "op", "path"} from structured fields and
    commands. `op` is the kernel op the tool produces: read, write, exec, or
    unknown."""
    actions: list[dict] = []
    for step in result.get("tool_log") or []:
        tool = step.get("tool") or ""
        op = ("read" if tool in TOOL_OP_READ else
              "write" if tool in TOOL_OP_WRITE else
              "exec" if tool == "Bash" else "unknown")
        raw = step.get("file_path") or step.get("path")
        if raw:
            actions.append({"tool": tool, "op": op, "path": raw})
        cmd = step.get("command") or ""
        for m in re.finditer(r"(?<![\w/.-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.*-]+)+)", cmd):
            actions.append({"tool": tool, "op": "exec", "path": m.group(1)})
    return actions


def find_rule(corpus: Path, repo: str, statement: str) -> Path | None:
    for cand in (corpus / repo / statement / "rule.yaml",
                 *(corpus / "*" / statement).glob("rule.yaml")):
        if Path(cand).exists():
            return Path(cand)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("corpus", help="extracted docs/corpus-test directory")
    ap.add_argument("artifact", help="extracted docs/artifact directory")
    ap.add_argument("rows", help="JSON rows array from audit_rq2_verdicts.js")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    corpus = Path(args.corpus)
    artifact = Path(args.artifact)
    rows = json.loads(Path(args.rows).read_text())
    if isinstance(rows, dict):
        rows = rows["rows"]
    fn_rows = [r for r in rows if r.get("system") == "actplane" and r.get("judgment") == "FN"]

    checked, exposures = 0, []
    for row in fn_rows:
        result_file = row.get("result_file")
        if not result_file:
            continue
        # `result_file` is relative to the artifact repo root; resolve it against
        # whichever ancestor of the artifact dir actually contains it.
        path = next((anc / result_file
                     for anc in [Path(args.artifact), *Path(args.artifact).parents]
                     if (anc / result_file).exists()), None)
        if path is None:
            continue
        result = json.loads(path.read_text())
        statement = result.get("statement_id") or path.parent.parent.name
        rule_yaml = find_rule(corpus, result["repo"].replace("/", "__"), statement)
        if not rule_yaml:
            continue
        checked += 1
        # File *sources* (`source L = file PAT`) match on read/open, so only a
        # read-op rule can be silenced by a missed source. A `file` pattern in a
        # rule target is a write/open sink; record which role each belongs to.
        rule_text = rule_yaml.read_text()
        source_patterns = set(re.findall(r'source\s+\w+\s*=\s*file\s+"([^"]+)"', rule_text))
        for pattern in re.findall(r'file "([^"]+)"', rule_text):
            kind, literal = replay.lower_path_current(pattern)
            if kind != replay.M_CONTAINS or not literal:
                continue
            core = literal.lstrip("/")
            role = "source" if pattern in source_patterns else "sink"
            # `te_materialize_file_source` runs on any successful open, so a file
            # source is matched on read *and* write opens; a sink only on its op.
            want_ops = {"read", "write"} if role == "source" else {"write"}
            for action in action_paths(result):
                observed = action["path"]
                if observed.startswith("/") or action["op"] not in want_ops:
                    continue
                # The pattern intends a repo-relative match; the lowered literal
                # misses it exactly when the recorded path is first-segment
                # relative (no leading slash to satisfy CONTAINS).
                if core in observed and literal not in observed:
                    exposures.append({
                        "repo": result["repo"],
                        "statement": statement,
                        "trace": result.get("trace_file"),
                        "role": role,
                        "pattern": pattern,
                        "lowered": f"{replay.lowered_name(kind)}({literal})",
                        "observed_tool": action["tool"],
                        "observed_op": action["op"],
                        "observed_path": observed,
                    })

    out = {
        "fn_rows_total": len(fn_rows),
        "fn_rows_with_frozen_rule": checked,
        "exposures": exposures,
        "note": ("Static exposure only, computed against the pre-fix "
                 "`contains(\"/dir/\")` primary. The artifact does not retain the "
                 "kernel's per-task matched path, so these rows are candidates "
                 "consistent with the lowering defect, not proven causation. The "
                 "defect's source/sink/gate roles are now fixed by the companion "
                 "`prefix(\"dir/\")` entry; this audit records which frozen FN rows "
                 "were exposed to it."),
    }
    print(json.dumps(out, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
