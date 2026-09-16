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
rule AND show a first-segment-relative action path in the recorded tool log,
i.e. are *exposed* to the defect? It is static exposure analysis over the frozen
records. It does not observe what path string the frozen kernel actually matched
(the artifact does not retain per-task kernel logs), so it identifies candidates
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


def action_paths(result: dict) -> set[str]:
    """Paths the recorded tools acted on, from structured fields and commands."""
    paths: set[str] = set()
    for step in result.get("tool_log") or []:
        for key in ("file_path", "path"):
            if step.get(key):
                paths.add(step[key])
        cmd = step.get("command") or ""
        for m in re.finditer(r"(?<![\w/.-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.*-]+)+)", cmd):
            paths.add(m.group(1))
    return paths


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
        patterns = re.findall(r'file "([^"]+)"', rule_yaml.read_text())
        for pattern in patterns:
            kind, literal = replay.lower_path_current(pattern)
            if kind != replay.M_CONTAINS or not literal:
                continue
            core = literal.lstrip("/")
            for observed in action_paths(result):
                if observed.startswith("/"):
                    continue
                # The pattern intends a repo-relative match; the lowered literal
                # misses it exactly when the recorded path is first-segment
                # relative (no leading slash to satisfy CONTAINS).
                if core in observed and literal not in observed:
                    exposures.append({
                        "repo": result["repo"],
                        "statement": statement,
                        "trace": result.get("trace_file"),
                        "pattern": pattern,
                        "lowered": f"{replay.lowered_name(kind)}({literal})",
                        "observed_path": observed,
                    })

    out = {
        "fn_rows_total": len(fn_rows),
        "fn_rows_with_frozen_rule": checked,
        "exposures": exposures,
        "note": ("Static exposure only. The artifact does not retain the kernel's "
                 "per-task matched path, so these rows are candidates consistent "
                 "with the lowering defect, not proven causation."),
    }
    print(json.dumps(out, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
