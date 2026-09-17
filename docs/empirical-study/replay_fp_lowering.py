#!/usr/bin/env python3
"""Evaluate whether the *current* ActPlane compiler still exhibits the path
lowering over-approximations that the RQ2 false-positive audit attributes to the
frozen 2026-06-07 compiler lineage.

`docs/empirical-study/rq2-fp-attribution.md` classifies the 18 ActPlane false
positives by the stage that first over-matched, and states an explicit boundary:
"The current implementation must be evaluated separately before claiming that any
historical lowering defect remains." This script performs that evaluation on the
host, with no live kernel:

  1. compile each frozen `rule.yaml` with a pinned `actplane` binary to the kernel
     ABI blob (`struct taint_config`, see bpf/taint.h);
  2. parse the lowered matchers (op, match kind, literal, unless-target condition)
     out of the blob: the ground truth for what today's compiler emits;
  3. port both `lower_path` implementations (historical at commit `cc3a9b11`,
     current at HEAD) to Python, assert the current port reproduces the blob
     byte-for-byte, then diff the two on every frozen FP target glob;
  4. replay the observed FP event through a faithful port of the kernel matcher
     predicates (bpf/taint.h) to state whether today's compiled matcher still
     fires on that event.

Deliverable: per FP row, whether today's compiled matcher still fires on the
recorded event ("still-fires"), no longer fires ("defect-resolved"), or newly
fires ("new-fire"), plus the exact historical-vs-current lowering of the
offending glob. `still-fires` does not by itself prove a lowering defect: the
`lowering_changes` field distinguishes a persisted lowering over-approximation
from a translated pattern that is genuinely broad, and the row keeps the
historical and current matcher replays side by side so either reading is
auditable. The script does not re-derive the frozen end-to-end 18/26/28 counts.

Everything is host-side matcher replay, not a live kernel verdict. The replay
uses the same string the frozen runner recorded as the matched target, which for
tracepoint-mode file events is the `TE_REF_USER_PATH` argument (relative when the
tool passed a relative path); the kernel matches that same string, so the replay
models the recorded event faithfully.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PAT = 64

# struct offsets verified against bpf/taint.h with offsetof.
RULE_SIZE = 224
RULE_FMT = f"<6B{PAT}s24s{PAT}s3QI"
UPD_SIZE = 144
UPDATE_FMT = f"<2B{PAT}s24s4Q"

M_EXACT, M_PREFIX, M_SUFFIX, M_ANY, M_CONTAINS = 0, 1, 2, 3, 4
MATCH_NAMES = {0: "exact", 1: "prefix", 2: "suffix", 3: "any", 4: "contains"}
OP_NAMES = {0: "exec", 1: "open", 2: "write", 3: "connect", 4: "recv"}
TCOND_TARGET = 3
EFFECT_NAMES = {0: "notify", 1: "block", 2: "kill"}
MAX_CONTAINS_LITERAL = 16  # mirrors TAINT_SUF_MAX / MAX_CONTAINS_LITERAL

# "**" is the local placeholder for the historical mid-pattern fallthrough.


def cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def _pad(x: str) -> bytes:
    b = x.encode("utf-8", "replace")[:PAT]
    return b + b"\0" * (PAT + 16 - len(b))


def m_streq(text: str, pat: str) -> bool:
    return _pad(text)[:PAT] == _pad(pat)[:PAT]


def kernel_match(kind: int, text: str, pat: str) -> bool:
    if kind == M_PREFIX:
        return bool(pat) and text.startswith(pat)
    if kind == M_SUFFIX:
        # taint_suffix: ordinary suffix, plus the slash-anchored bare-root form.
        # The compiler lowers a globstar-basename pattern to "/<name>", which
        # must also match the bare root-level name (text == pat[1:]).
        if not pat or len(pat) > 16:
            return False
        if pat.startswith("/") and text == pat[1:]:
            return True
        return text.endswith(pat)
    if kind == M_ANY:
        return True
    if kind == M_CONTAINS:
        return bool(pat) and pat in text
    return m_streq(text, pat)


# ---- ported lower_path implementations -------------------------------------
def shorten_contains_literal(lit: str) -> str:
    if len(lit) <= MAX_CONTAINS_LITERAL:
        return lit
    trimmed = lit.lstrip("/")
    if len(trimmed) <= MAX_CONTAINS_LITERAL:
        return trimmed
    for idx, _ in [(i, c) for i, c in enumerate(trimmed) if c == "/"]:
        cand = trimmed[idx + 1:]
        if cand and len(cand) <= MAX_CONTAINS_LITERAL:
            return cand
    last = trimmed.rsplit("/", 1)[-1]
    if last and len(last) <= MAX_CONTAINS_LITERAL:
        return last
    return trimmed[len(trimmed) - MAX_CONTAINS_LITERAL:]


def shorten_repo_relative_exact_literal(path: str) -> str:
    if len(path) <= MAX_CONTAINS_LITERAL:
        return path
    for idx, c in enumerate(path):
        if c == "/":
            cand = path[idx + 1:]
            if "/" in cand and len(cand) <= MAX_CONTAINS_LITERAL:
                return cand
    if "/" in path:
        parent = path.rsplit("/", 1)[0]
        return shorten_contains_literal(parent + "/")
    return shorten_contains_literal(path)


def lower_path_current(pat: str) -> tuple[int, str]:
    """Current bpf/crates/actplane-ifc-compiler/src/dsl/lower.rs::lower_path."""
    if pat in ("*", "**", "**/*"):
        return (M_ANY, "")
    repo_relative = not pat.startswith("/")
    if pat.startswith("**/") and pat.endswith("/**"):
        inner = pat[3:-3]
        if "*" not in inner:
            return (M_CONTAINS, shorten_contains_literal(f"/{inner}/"))
    if pat.startswith("**/") and pat.endswith("/*"):
        inner = pat[3:-2]
        if "*" not in inner:
            return (M_CONTAINS, shorten_contains_literal(f"/{inner}/"))
    if pat.startswith("**/"):
        inner = pat[3:]
        if inner.startswith("*"):
            return (M_SUFFIX, inner[1:])
        if "*" not in inner:
            return (M_SUFFIX, "/" + inner)
        return (M_CONTAINS, shorten_contains_literal(inner))
    if pat.endswith("/**"):
        p = pat[:-3]
        if repo_relative:
            if "*" not in p:
                return (M_CONTAINS, shorten_contains_literal(f"{p}/"))
        else:
            return (M_PREFIX, f"{p}/")
    if pat.endswith("**"):
        p = pat[:-2]
        if repo_relative:
            if "*" not in p:
                return (M_CONTAINS, shorten_contains_literal(p))
        else:
            return (M_PREFIX, p)
    if pat.endswith("/*"):
        p = pat[:-2]
        if repo_relative:
            if "*" not in p:
                return (M_CONTAINS, shorten_contains_literal(f"{p}/"))
        else:
            return (M_PREFIX, f"{p}/")
    if pat.startswith("*"):
        p = pat[1:]
        if repo_relative:
            return (M_CONTAINS, shorten_contains_literal(p))
        return (M_SUFFIX, p)
    if "*" in pat:
        idx = pat.index("*")
        if repo_relative:
            return (M_CONTAINS, shorten_contains_literal(pat[:idx]))
        return (M_PREFIX, pat[:idx])
    if repo_relative and "/" in pat:
        return (M_CONTAINS, shorten_repo_relative_exact_literal(pat))
    if repo_relative:
        return (M_CONTAINS, shorten_contains_literal(pat))
    return (M_EXACT, pat)


def lower_path_historical(pat: str) -> tuple[int, str]:
    """Historical lower_path at commit cc3a9b11 (collector/src/dsl/lower.rs).

    The only differences from the current version are the two `**/...` branches:
    the historical compiler lowered `**/foo` to CONTAINS("foo") and `**/*.ext`
    to CONTAINS(".ext"), while the current compiler lowers them to SUFFIX.
    """
    if pat in ("*", "**", "**/*"):
        return (M_ANY, "")
    repo_relative = not pat.startswith("/")
    if pat.startswith("**/") and pat.endswith("/**"):
        inner = pat[3:-3]
        if "*" not in inner:
            return (M_CONTAINS, shorten_contains_literal(f"/{inner}/"))
    if pat.startswith("**/") and pat.endswith("/*"):
        inner = pat[3:-2]
        if "*" not in inner:
            return (M_CONTAINS, shorten_contains_literal(f"/{inner}/"))
    if pat.startswith("**/"):
        inner = pat[3:]
        if inner.startswith("*"):
            return (M_CONTAINS, shorten_contains_literal(inner[1:]))
        return (M_CONTAINS, shorten_contains_literal(inner))
    if pat.endswith("/**"):
        p = pat[:-3]
        if repo_relative:
            if "*" not in p:
                return (M_CONTAINS, shorten_contains_literal(f"{p}/"))
        else:
            return (M_PREFIX, f"{p}/")
    if pat.endswith("**"):
        p = pat[:-2]
        if repo_relative:
            if "*" not in p:
                return (M_CONTAINS, shorten_contains_literal(p))
        else:
            return (M_PREFIX, p)
    if pat.endswith("/*"):
        p = pat[:-2]
        if repo_relative:
            if "*" not in p:
                return (M_CONTAINS, shorten_contains_literal(f"{p}/"))
        else:
            return (M_PREFIX, f"{p}/")
    if pat.startswith("*"):
        p = pat[1:]
        if repo_relative:
            return (M_CONTAINS, shorten_contains_literal(p))
        return (M_SUFFIX, p)
    if "*" in pat:
        idx = pat.index("*")
        if repo_relative:
            return (M_CONTAINS, shorten_contains_literal(pat[:idx]))
        return (M_PREFIX, pat[:idx])
    if repo_relative and "/" in pat:
        return (M_CONTAINS, shorten_repo_relative_exact_literal(pat))
    if repo_relative:
        return (M_CONTAINS, shorten_contains_literal(pat))
    return (M_EXACT, pat)


def lower_exec_current(pat: str) -> tuple[int, str]:
    """Current lower_exec (crates/.../dsl/lower.rs::lower_exec)."""
    if pat in ("*", "**", "**/*"):
        return (M_ANY, "")
    base = pat.rsplit("/", 1)[-1]
    if base.endswith("*"):
        return (M_PREFIX, base[:-1])
    return (M_EXACT, base)


def lower_exec_historical(pat: str) -> tuple[int, str]:
    """Historical lower_exec at commit cc3a9b11: no bare-star special case."""
    base = pat.rsplit("/", 1)[-1]
    if base.endswith("*"):
        return (M_PREFIX, base[:-1])
    return (M_EXACT, base)


def lowered_name(kind: int) -> str:
    return MATCH_NAMES.get(kind, str(kind))




def extract_unless_glob(clause_text: str) -> str | None:
    m = re.search(r'unless\s+target\s+"([^"]*)"', clause_text or "")
    return m.group(1) if m else None


# ---- blob parse ------------------------------------------------------------
def parse_config(blob: bytes) -> dict:
    n_updates, n_rules = struct.unpack_from("<II", blob, 0)
    rules_base = 8 + UPD_SIZE * 320
    rules = []
    for i in range(n_rules):
        base = rules_base + i * RULE_SIZE
        (op, m, ck, cn, cm, eff, target, arg, cond_pat,
         req, forbid, gate, rule_id) = struct.unpack_from(RULE_FMT, blob, base)
        rules.append({
            "index": i,
            "op": OP_NAMES.get(op, op),
            "match": MATCH_NAMES.get(m, m),
            "match_kind": m,
            "target": cstr(target),
            "arg": cstr(arg),
            "cond_kind": ck,
            "cond_neg": bool(cn),
            "cond_match_kind": cm,
            "cond_match": MATCH_NAMES.get(cm, cm),
            "cond_pat": cstr(cond_pat),
            "effect": EFFECT_NAMES.get(eff, eff),
            "rule_id": rule_id,
        })
    return {"n_updates": n_updates, "n_rules": n_rules, "rules": rules}


def fires_with(rules, targets, unlesses, event_op, event_text):
    """Does any rule fire for the event, given per-rule (match, literal) targets
    and unless conditions? `rules[i]['op']` supplies the operation."""
    cands = [event_text]
    if event_op == "exec":
        cands = [event_text.rsplit("/", 1)[-1], event_text]
    hits = []
    for i, rule in enumerate(rules):
        if rule["op"] != event_op:
            continue
        kind, lit = targets[i]
        fired = any(kernel_match(kind, c, lit) for c in cands)
        entry = {"rule_index": i, "lowered_as": f"{lowered_name(kind)}(\"{lit}\")", "target_match": fired}
        uk = None
        if unlesses and unlesses[i]:
            ukind, ulit = unlesses[i]
            hit = any(kernel_match(ukind, c, ulit) for c in cands)
            entry["unless_lowered_as"] = f"{lowered_name(ukind)}(\"{ulit}\")"
            entry["unless_match"] = hit
            fired = fired and not hit
        entry["fires"] = fired
        hits.append(entry)
    return any(h["fires"] for h in hits), hits



def selftest() -> int:
    """Pin the ported lowerings and the kernel matcher against known facts.

    These assertions double as the check that the ports have not silently
    drifted from the compiler they model. Run with `--selftest`.
    """
    checks = []

    def check(cond, name):
        checks.append((bool(cond), name))

    # Current lowering, mirrored from lower.rs unit tests.
    check(lower_path_current("**/*.js") == (M_SUFFIX, ".js"), "current **/*.js -> suffix(.js)")
    check(lower_path_current("**/sec.env") == (M_SUFFIX, "/sec.env"), "current **/sec.env -> suffix(/sec.env)")
    check(lower_path_current("**/*") == (M_ANY, ""), "current **/* -> any")
    check(lower_path_current("**/dist/**") == (M_CONTAINS, "/dist/"), "current **/dist/** -> contains(/dist/)")
    check(lower_path_current("/tmp/guarded/**") == (M_PREFIX, "/tmp/guarded/"), "current absolute dir -> prefix")
    check(lower_path_current("/tmp/guarded/f.txt") == (M_EXACT, "/tmp/guarded/f.txt"), "current absolute file -> exact")
    # Historical difference: `**/x` was CONTAINS, not SUFFIX.
    check(lower_path_historical("**/*.js") == (M_CONTAINS, ".js"), "historical **/*.js -> contains(.js)")
    check(lower_path_historical("**/sec.env") == (M_CONTAINS, "sec.env"), "historical **/sec.env -> contains(sec.env)")

    # Kernel matcher semantics.
    check(kernel_match(M_SUFFIX, "/a/b/x.js", ".js") is True, "suffix matches extension")
    check(kernel_match(M_SUFFIX, "x.js.txt", ".js") is False, "suffix rejects .js.txt")
    check(kernel_match(M_CONTAINS, "/w/dist/x.js", "/dist/") is True, "contains /dist/ hits absolute")
    check(kernel_match(M_CONTAINS, "dist/x.js", "/dist/") is False, "contains /dist/ misses relative dist/")

    # The contains -> suffix tightening changed `**/<name>` from CONTAINS to
    # SUFFIX("/<name>"), which stopped matching a bare root-level relative file
    # (`suffix("/.env")` needs a slash). The fix folds the bare-root form into
    # taint_suffix: a slash-anchored suffix also matches its literal without the
    # leading slash, so both the bare name and the slash-anchored nested form
    # match, with no new matcher kind (the inlined call graph is unchanged).
    check(lower_path_current("**/.env") == (M_SUFFIX, "/.env"), "current **/.env -> suffix(/.env)")
    check(lower_path_historical("**/.env") == (M_CONTAINS, ".env"), "historical **/.env -> contains(.env)")
    check(kernel_match(M_SUFFIX, ".env", "/.env") is True, "suffix(/.env) matches bare .env (fold)")
    check(kernel_match(M_SUFFIX, "sub/.env", "/.env") is True, "suffix(/.env) matches nested .env")
    check(kernel_match(M_SUFFIX, "/work/.env", "/.env") is True, "suffix(/.env) matches absolute .env")
    check(kernel_match(M_SUFFIX, "foo.env", "/.env") is False, "suffix(/.env) rejects the foo.env suffix")
    check(kernel_match(M_SUFFIX, "a/.env.bak", "/.env") is False, "suffix(/.env) rejects a longer name")

    for ok, name in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    failed = sum(1 for ok, _ in checks if not ok)
    print(f"\n{len(checks) - failed} passed, {failed} failed")
    return 1 if failed else 0

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true", help="run ported-lowering assertions and exit")
    ap.add_argument("corpus_root", nargs="?", help="dir containing <repo>/<statement>/rule.yaml")
    ap.add_argument("fp_rows", nargs="?", help="JSON rows array from audit_rq2_verdicts.js")
    ap.add_argument("cli", nargs="?", default="target/release/actplane", help="pinned actplane binary")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.corpus_root or not args.fp_rows:
        ap.error("corpus_root and fp_rows are required unless --selftest is given")

    corpus = Path(args.corpus_root)
    rows = json.loads(Path(args.fp_rows).read_text())
    if isinstance(rows, dict):
        rows = rows["rows"]
    fps = [r for r in rows if r.get("system") == "actplane" and r.get("judgment") == "FP"]

    work = Path("/tmp/actplane-fp-replay")
    work.mkdir(exist_ok=True)
    out_rows = []
    port_mismatches = []
    for r in fps:
        repo_key = r["repo"].replace("/", "__")
        stmt = r["statement"]
        rule_yaml = next((c for c in corpus.rglob("rule.yaml")
                          if c.parent.name == stmt and c.parent.parent.name == repo_key), None)
        if rule_yaml is None:
            out_rows.append({"repo": r["repo"], "statement": stmt, "error": "rule.yaml not found"})
            continue
        blob = work / f"{repo_key}__{stmt}.bin"
        subprocess.run([args.cli, "compile", "--policy", str(rule_yaml), "--out", str(blob), "--force"],
                       check=True, capture_output=True)
        cfg = parse_config(blob.read_bytes())
        # `compile --json` exposes the original DSL target glob (and clause text)
        # per lowered rule.
        report = json.loads(subprocess.run([args.cli, "compile", "--policy", str(rule_yaml), "--json"],
                                           check=True, capture_output=True).stdout)
        json_rules = report.get("rules", [])
        globs = [rule.get("target_pattern") for rule in json_rules]
        unless_globs = [extract_unless_glob(rule.get("clause_text", "")) for rule in json_rules]

        target = (r.get("target") or "").strip()
        event_op = target.split(" ", 1)[0] if target else ""
        event_text = target.split(" ", 1)[1] if " " in target else ""

        # Validate the current lowering port against the compiled blob, and build
        # the historical and current (match, literal) targets per rule.
        port_rows, lowering_changes = [], []
        cur_targets, hist_targets, cur_unless, hist_unless = [], [], [], []
        for idx, rule in enumerate(cfg["rules"]):
            glob = globs[idx] if idx < len(globs) else rule["target"]
            is_exec = rule["op"] == "exec"
            cur = lower_exec_current(glob) if is_exec else lower_path_current(glob)
            hist = lower_exec_historical(glob) if is_exec else lower_path_historical(glob)
            cur_targets.append(cur)
            hist_targets.append(hist)
            ok = (cur[0] == rule["match_kind"] and cur[1] == rule["target"])
            if not ok:
                port_mismatches.append({"repo": r["repo"], "statement": stmt, "glob": glob,
                                        "blob": f"{rule['match']}({rule['target']})",
                                        "port": f"{lowered_name(cur[0])}({cur[1]})"})
            if hist != cur:
                lowering_changes.append({"which": "target", "glob": glob, "op": rule["op"],
                                         "historical": f"{lowered_name(hist[0])}({hist[1]})",
                                         "current": f"{lowered_name(cur[0])}({cur[1]})"})
            ug = unless_globs[idx] if idx < len(unless_globs) else None
            if ug and rule["cond_kind"] == TCOND_TARGET:
                ucur, uhist = lower_path_current(ug), lower_path_historical(ug)
                cur_unless.append(ucur)
                hist_unless.append(uhist)
                if not (ucur[0] == rule["cond_match_kind"] and ucur[1] == rule["cond_pat"]):
                    port_mismatches.append({"repo": r["repo"], "statement": stmt, "glob": ug,
                                            "which": "unless",
                                            "blob": f"{rule['cond_match']}({rule['cond_pat']})",
                                            "port": f"{lowered_name(ucur[0])}({ucur[1]})"})
                if uhist != ucur:
                    lowering_changes.append({"which": "unless", "glob": ug, "op": rule["op"],
                                             "historical": f"{lowered_name(uhist[0])}({uhist[1]})",
                                             "current": f"{lowered_name(ucur[0])}({ucur[1]})"})
            else:
                cur_unless.append(None)
                hist_unless.append(None)
            port_rows.append({"glob": glob, "op": rule["op"], "unless_glob": ug,
                              "blob": f"{rule['match']}({rule['target']})",
                              "port": f"{lowered_name(cur[0])}({cur[1]})", "port_matches_blob": ok})

        # Today's matcher necessarily equals the compiled blob (validated above);
        # compare it against the historical lowering replayed on the same event.
        cur_hit, cur_detail = fires_with(cfg["rules"], cur_targets, cur_unless, event_op, event_text)
        hist_hit, hist_detail = fires_with(cfg["rules"], hist_targets, hist_unless, event_op, event_text)
        # Neutral labels: the audit reports whether today's compiled matcher still
        # fires on the recorded event. Whether that over-match comes from the
        # lowering or from the translated pattern is carried by lowering_changes.
        if cur_hit and hist_hit:
            classification = "still-fires"
        elif cur_hit and not hist_hit:
            classification = "new-fire"
        elif hist_hit and not cur_hit:
            classification = "defect-resolved"
        else:
            classification = "never-fires"

        out_rows.append({
            "repo": r["repo"],
            "statement": stmt,
            "trace": r["trace"],
            "observed_event": target,
            "historical_lowering_fires": hist_hit,
            "current_lowering_fires": cur_hit,
            "lowering_changes": lowering_changes,
            "classification": classification,
            "port_check": port_rows,
            "current_detail": cur_detail,
            "historical_detail": hist_detail,
        })

    summary: dict[str, int] = {}
    for row in out_rows:
        summary[row.get("classification", "error")] = summary.get(row.get("classification", "error"), 0) + 1
    result = {
        "summary": summary,
        "port_mismatches": port_mismatches,
        "rows": out_rows,
    }
    print(json.dumps(result, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2))
    # Fail closed: this audit is only meaningful if the ported lowering exactly
    # reproduces the compiled blob for every rule, and every FP row compiled.
    errors = [r for r in out_rows if r.get("error")]
    if port_mismatches:
        print(f"ERROR: {len(port_mismatches)} lowering port(s) disagree with the compiled blob", file=sys.stderr)
        return 1
    if errors or len(out_rows) != len(fps):
        print(f"ERROR: {len(errors)} FP row(s) failed to compile", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
