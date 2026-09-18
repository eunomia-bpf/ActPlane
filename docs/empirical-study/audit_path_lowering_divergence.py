#!/usr/bin/env python3
"""Find frozen RQ2 rules whose coverage changed between the historical
(2026-06-07) and current path lowering, restricted to the two relative-path
defects documented in `rq2-lowering-eval.md`.

The current compiler differs from the historical one in two relevant ways:

  1. `**/dir/**` -> `CONTAINS("/dir/")` (unchanged primary, but the current
     compiler pairs it with a companion `PREFIX("dir/")`; the primary needs a
     slash before the directory, so without the companion a
     first-segment-relative path in tracepoint mode is mis-matched); and
  2. `**/<name>` -> `SUFFIX("/<name>")` (changed from `CONTAINS("<name>")`,
     paired with a companion `EXACT("<name>")`), which stops matching a bare
     root-level relative file such as `.env`.

This scan reports, per frozen rule, whether a pattern's historical and current
lowerings disagree on a *bare relative* path (single segment, no leading slash),
a *first-segment-relative* path, or an *absolute* path, i.e. the concrete
relative-path conditions. It is static: it compares lowerings and their matcher
results, not a live kernel verdict.

Input: --corpus, the extracted `docs/corpus-test` directory.
"""

from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("replay_fp_lowering", _HERE / "replay_fp_lowering.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


def bare_segment(pattern: str) -> str | None:
    """The `**/<seg>` trailing segment (no slash, no wildcard), else None."""
    if not pattern.startswith("**/"):
        return None
    seg = pattern[3:]
    if not seg or "/" in seg or "*" in seg:
        return None
    return seg


def dir_segment(pattern: str) -> str | None:
    """The `**/<dir>/**` or `**/<dir>/*` directory (no wildcard), else None."""
    if not pattern.startswith("**/"):
        return None
    for suffix in ("/**", "/*"):
        if pattern.endswith(suffix):
            inner = pattern[3 : -len(suffix)]
            if inner and "*" not in inner:
                return inner
            return None
    return None


def probe_paths(pattern: str) -> dict[str, str]:
    """Shape-correct probe paths for a `**/...` pattern: a `**/<name>` basename
    pattern is probed at the bare name, nested, and absolute; a `**/<dir>/**`
    directory pattern is probed at the directory reached from the root
    (first-segment), nested, and absolute. Other patterns fall back to a
    single-segment name."""
    seg = bare_segment(pattern)
    if seg is not None:
        return {
            "bare_relative": seg,
            "nested_relative": f"sub/{seg}",
            "absolute": f"/work/{seg}",
        }
    dseg = dir_segment(pattern)
    if dseg is not None:
        return {
            "first_segment_relative": f"{dseg}/x.js",
            "nested_relative": f"sub/{dseg}/x.js",
            "absolute": f"/work/{dseg}/x.js",
        }
    name = pattern.rsplit("/", 1)[-1] or "target"
    return {
        "bare_relative": name,
        "nested_relative": f"sub/{name}",
        "absolute": f"/work/{name}",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("corpus", help="extracted docs/corpus-test directory")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    corpus = Path(args.corpus)
    findings = []
    for rule_yaml in sorted(glob.glob(str(corpus / "**" / "rule.yaml"), recursive=True)):
        text = Path(rule_yaml).read_text()
        rel = os.path.relpath(rule_yaml, corpus)
        for pattern in sorted(set(re.findall(r'file "([^"]+)"', text))):
            hist = replay.lower_path_historical(pattern)
            cur = replay.lower_path_current(pattern)
            # The current compiler also emits repo-relative companion entries (the
            # `**/<name>` bare name and the `**/<dir>/**` first-segment form);
            # model the full current lowering, not just its primary form.
            cur_extras = replay.lower_path_companions(pattern)
            if hist == cur and not cur_extras:
                continue
            probes = probe_paths(pattern)
            diffs = []
            for form, path in probes.items():
                h = bool(replay.kernel_match(hist[0], path, hist[1]))
                c = bool(replay.kernel_match(cur[0], path, cur[1]))
                for ekind, elit in cur_extras:
                    c = c or bool(replay.kernel_match(ekind, path, elit))
                if h != c:
                    # `expansion`: current matches a probe the historical form
                    # missed (the `**/dir/**` companion adds the first-segment
                    # form). `narrowing`: current rejects a probe the historical
                    # form matched (the `**/<name>` contains -> suffix/exact
                    # tightening rounding a component boundary).
                    diffs.append({"form": form, "path": path,
                                  "historical_fires": h, "current_fires": c,
                                  "direction": "expansion" if c else "narrowing"})
            if diffs:
                extras = "".join(f"+{replay.lowered_name(k)}({l})" for k, l in cur_extras)
                directions = sorted({d["direction"] for d in diffs})
                findings.append({
                    "rule": rel,
                    "pattern": pattern,
                    "historical": f"{replay.lowered_name(hist[0])}({hist[1]})",
                    "current": f"{replay.lowered_name(cur[0])}({cur[1]})" + extras,
                    "directions": directions,
                    "divergences": diffs,
                })

    out = {
        "corpus": str(corpus),
        "note": ("Static lowering comparison over frozen rule patterns. A "
                 "divergence means the current compiler matches a probe path "
                 "differently from the historical one; it is not a statement "
                 "about any frozen run's actual matched path."),
        "findings": findings,
    }
    print(json.dumps(out, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
