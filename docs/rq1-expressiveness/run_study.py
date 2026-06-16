#!/usr/bin/env python3
"""Run the RQ1 DSL expressiveness and generation-cost study."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
RQ_DIR = ROOT / "docs" / "rq1-expressiveness"
CORPUS_ROOT = ROOT / "docs" / "corpus"
CORPUS_EVALUATED_ROOT = ROOT / "docs" / "corpus-evaluated"
OUT_BASE = ROOT / "docs" / "eval_runs" / "rq1-expressiveness"
PROMPT_TEMPLATE = RQ_DIR / "translation_prompt.md"
SUPPORTED_ENFORCEABILITY = {"per_event", "cross_event"}
EXPECTED_COUNTS = {"per_event": 392, "cross_event": 215}
EXPECTED_TOTAL = 607


try:
    import tiktoken  # type: ignore

    _TOKEN_ENCODER = tiktoken.get_encoding("cl100k_base")
    TOKENIZER_NAME = "tiktoken:cl100k_base"
except Exception:
    _TOKEN_ENCODER = None
    TOKENIZER_NAME = "regex-estimate"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def count_tokens(text: str) -> int:
    if _TOKEN_ENCODER is not None:
        return len(_TOKEN_ENCODER.encode(text))
    return len(re.findall(r"\w+|[^\w\s]", text, flags=re.UNICODE))


def now_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def safe_component(value: Any) -> str:
    text = str(value)
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")
    return text or "item"


def load_directives(corpus_root: Path = CORPUS_ROOT) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for statements_path in sorted(corpus_root.glob("*/statements.yaml")):
        repo_dir = statements_path.parent.name
        data = yaml.safe_load(statements_path.read_text(encoding="utf-8")) or {}
        meta_path = statements_path.parent / "meta.json"
        meta = read_json(meta_path) if meta_path.exists() else {}
        source_file = data.get("file")
        for statement in data.get("statements", []):
            if statement.get("type") != "directive":
                continue
            enforceability = statement.get("enforceability")
            if enforceability not in SUPPORTED_ENFORCEABILITY:
                continue

            statement_id = str(statement.get("id"))
            directive = str(statement.get("text", "")).strip()
            uid = f"{repo_dir}::{statement_id}"
            item = {
                "uid": uid,
                "repo_dir": repo_dir,
                "repo": meta.get("repo", repo_dir.replace("__", "/")),
                "statement_id": statement_id,
                "source_file": source_file,
                "lines": statement.get("lines"),
                "directive": directive,
                "topic": statement.get("topic"),
                "enforceability": enforceability,
                "context_required": statement.get("context_required"),
                "confidence": statement.get("confidence"),
                "language": meta.get("language"),
                "stars": meta.get("stars"),
                "nl_tokens": count_tokens(directive),
                "tokenizer": TOKENIZER_NAME,
            }
            items.append(item)
    return items


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def manifest_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(item["enforceability"] for item in items)
    return {
        "total": len(items),
        "counts": dict(sorted(counts.items())),
        "expected_total": EXPECTED_TOTAL,
        "expected_counts": EXPECTED_COUNTS,
        "matches_expected": len(items) == EXPECTED_TOTAL and all(counts.get(k, 0) == v for k, v in EXPECTED_COUNTS.items()),
        "tokenizer": TOKENIZER_NAME,
    }


def command_manifest(args: argparse.Namespace) -> int:
    items = load_directives(Path(args.corpus_root))
    out = Path(args.out) if args.out else RQ_DIR / "directives.jsonl"
    write_jsonl(out, items)
    summary = manifest_summary(items)
    write_json(out.with_suffix(".summary.json"), summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["matches_expected"]:
        print(
            f"warning: manifest counts do not match expected {EXPECTED_COUNTS} total {EXPECTED_TOTAL}",
            file=sys.stderr,
        )
        return 2 if args.strict else 0
    return 0


def read_context(item: dict[str, Any], *, embed_context: bool, max_chars: int, tree_files: int) -> str:
    repo_root = CORPUS_ROOT / item["repo_dir"]
    evaluated_repo = CORPUS_EVALUATED_ROOT / item["repo_dir"] / "repo"
    lines = [
        f"corpus directory: {rel(repo_root)}",
        f"evaluated repo clone: {rel(evaluated_repo)}" if evaluated_repo.exists() else "evaluated repo clone: not available",
        "DSL reference: docs/rule-language.md",
    ]

    if evaluated_repo.exists() and tree_files > 0:
        file_names: list[str] = []
        for root, dirs, files in os.walk(evaluated_repo):
            dirs[:] = [d for d in sorted(dirs) if d not in {".git", "node_modules", "target", ".venv", "__pycache__"}]
            for name in sorted(files):
                path = Path(root) / name
                file_names.append(rel(path))
                if len(file_names) >= tree_files:
                    break
            if len(file_names) >= tree_files:
                break
        if file_names:
            lines.append("repo file sample:")
            lines.extend(f"  {name}" for name in file_names)

    if not embed_context:
        return "\n".join(lines)

    context_parts: list[str] = []
    for name in ("AGENTS.md", "CLAUDE.md"):
        path = repo_root / name
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if len(text) > max_chars:
                text = text[:max_chars] + "\n...[truncated]..."
            context_parts.append(f"--- {rel(path)} ---\n{text}")

    if context_parts:
        lines.append("\nInstruction file excerpts:")
        lines.append("\n\n".join(context_parts))
    return "\n".join(lines)


def render_prompt(item: dict[str, Any], context: str, previous_error: str) -> str:
    template = Template(PROMPT_TEMPLATE.read_text(encoding="utf-8"))
    return template.safe_substitute(
        ITEM_JSON=json.dumps(item, indent=2, sort_keys=True, ensure_ascii=False),
        CONTEXT=context,
        PREVIOUS_ERROR=previous_error or "None.",
    )


def run_translator(
    prompt: str,
    *,
    translator: str,
    translator_cmd: str | None,
    codex_args: list[str],
    codex_configs: list[str],
    prompt_file: Path,
    out_file: Path,
    timeout: float,
) -> tuple[int, str, str, float]:
    start = time.monotonic()
    if translator == "codex":
        config_args = [part for cfg in codex_configs for part in ("-c", cfg)]
        cmd = ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", *config_args, *codex_args, prompt]
        stdin = None
    elif translator == "cmd":
        if not translator_cmd:
            raise ValueError("--translator-cmd is required when --translator cmd")
        rendered = translator_cmd.format(prompt_file=str(prompt_file), out_file=str(out_file))
        cmd = shlex.split(rendered)
        stdin = None if "{prompt_file}" in translator_cmd or "{out_file}" in translator_cmd else prompt
    else:
        raise ValueError(f"unknown translator: {translator}")

    proc = subprocess.run(
        cmd,
        input=stdin,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    elapsed = time.monotonic() - start
    stdout = proc.stdout
    if out_file.exists() and not stdout.strip():
        stdout = out_file.read_text(encoding="utf-8", errors="replace")
    return proc.returncode, stdout, proc.stderr, elapsed


def parse_codex_total_tokens(text: str) -> int | None:
    matches = re.findall(r"tokens used\s+([0-9][0-9,]*)", text, flags=re.IGNORECASE)
    if not matches:
        return None
    return int(matches[-1].replace(",", ""))


def strip_fence(text: str) -> str:
    text = text.strip()
    fence = re.search(r"```(?:json|yaml|yml)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        return fence.group(1).strip()
    return text


def extract_json_object(text: str) -> dict[str, Any] | None:
    candidate = strip_fence(text)
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def normalize_policy(raw: Any, full_response: str) -> tuple[str | None, str]:
    if isinstance(raw, dict):
        policy = raw.get("policy")
        notes = str(raw.get("notes", ""))
    elif isinstance(raw, str):
        policy = raw
        notes = ""
    else:
        parsed = extract_json_object(full_response)
        if parsed is not None:
            return normalize_policy(parsed, full_response)
        policy = strip_fence(full_response)
        notes = "parsed as raw policy"

    if policy is None:
        return None, notes
    if not isinstance(policy, str):
        return None, notes
    policy = strip_fence(policy).strip()
    if not policy or policy.lower() in {"null", "none"}:
        return None, notes

    stripped = policy.lstrip()
    if stripped.startswith("version:"):
        return policy.rstrip() + "\n", notes
    if stripped.startswith("policy:"):
        return "version: 1\n" + policy.rstrip() + "\n", notes

    body = "\n".join(("  " + line if line else "") for line in policy.splitlines())
    return f"version: 1\npolicy: |\n{body.rstrip()}\n", notes


def locate_actplane(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(ROOT / "target" / "release" / "actplane")
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("actplane")
    if found:
        return Path(found)
    raise FileNotFoundError("could not find actplane; build it or pass --actplane")


def categorize_compile_error(text: str) -> str:
    lower = text.lower()
    if not text.strip():
        return "unknown"
    if "yaml" in lower or "policy file" in lower or "version" in lower:
        return "policy_yaml"
    if "parse" in lower or "expected" in lower or "unexpected" in lower:
        return "dsl_parse"
    if "unknown" in lower or "undefined" in lower:
        return "unknown_symbol"
    if "too many" in lower or "max_" in lower or "exceeds" in lower:
        return "abi_limit"
    if "invalid" in lower:
        return "invalid_policy"
    return "compiler_error"


def compile_policy(actplane: Path, policy_path: Path, bin_path: Path, timeout: float) -> dict[str, Any]:
    start = time.monotonic()
    proc = subprocess.run(
        [str(actplane), "--policy", str(policy_path), "compile", "--out", str(bin_path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    elapsed = time.monotonic() - start
    combined = (proc.stdout or "") + (proc.stderr or "")
    ok = proc.returncode == 0 and bin_path.exists()
    return {
        "ok": ok,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "elapsed_s": elapsed,
        "error_category": None if ok else categorize_compile_error(combined),
        "binary_size": bin_path.stat().st_size if ok else None,
    }


def existing_successes(results_path: Path) -> dict[str, dict[str, Any]]:
    rows = read_jsonl(results_path)
    return {row.get("uid"): row for row in rows if row.get("uid") and row.get("status") == "compiled"}


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def command_translate(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir) if args.run_dir else OUT_BASE / now_id()
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = run_dir / "directives.jsonl"
    items = load_directives(Path(args.corpus_root))
    if args.limit is not None:
        items = items[: args.limit]
    write_jsonl(manifest_path, items)
    write_json(run_dir / "manifest_summary.json", manifest_summary(items))

    actplane = locate_actplane(args.actplane)
    results_path = run_dir / "results.jsonl"
    completed = existing_successes(results_path) if args.resume else {}

    for idx, item in enumerate(items, start=1):
        uid = item["uid"]
        if uid in completed:
            print(f"[{idx}/{len(items)}] skip compiled {uid}")
            continue

        repo_part = safe_component(item["repo_dir"])
        stmt_part = safe_component(item["statement_id"])
        item_dir = Path(repo_part) / stmt_part
        prompt_dir = run_dir / "prompts" / item_dir
        response_dir = run_dir / "responses" / item_dir
        policy_dir = run_dir / "policies" / item_dir
        compile_dir = run_dir / "compile_logs" / item_dir
        for directory in (prompt_dir, response_dir, policy_dir, compile_dir):
            directory.mkdir(parents=True, exist_ok=True)

        previous_error = ""
        attempt_records: list[dict[str, Any]] = []
        final_policy: str | None = None
        final_compile: dict[str, Any] | None = None
        final_status = "failed"
        final_reason = "not_attempted"
        start_item = time.monotonic()

        for attempt in range(1, args.max_attempts + 1):
            context = read_context(
                item,
                embed_context=not args.no_embed_context,
                max_chars=args.max_context_chars,
                tree_files=args.tree_files,
            )
            prompt = render_prompt(item, context, previous_error)
            prompt_file = prompt_dir / f"attempt{attempt}.prompt.md"
            raw_out_file = response_dir / f"attempt{attempt}.out"
            prompt_file.write_text(prompt, encoding="utf-8")

            print(f"[{idx}/{len(items)}] {uid} attempt {attempt}")
            attempt_record: dict[str, Any] = {
                "attempt": attempt,
                "prompt_tokens": count_tokens(prompt),
                "translator": args.translator,
                "tokenizer": TOKENIZER_NAME,
            }
            try:
                rc, stdout, stderr, translator_elapsed = run_translator(
                    prompt,
                    translator=args.translator,
                    translator_cmd=args.translator_cmd,
                    codex_args=args.codex_arg or [],
                    codex_configs=args.codex_config or [],
                    prompt_file=prompt_file,
                    out_file=raw_out_file,
                    timeout=args.translator_timeout,
                )
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
                rc = 124
                translator_elapsed = args.translator_timeout
            raw_out_file.write_text(stdout, encoding="utf-8", errors="replace")
            (response_dir / f"attempt{attempt}.stderr").write_text(stderr, encoding="utf-8", errors="replace")
            attempt_record.update(
                {
                    "translator_returncode": rc,
                    "translator_elapsed_s": translator_elapsed,
                    "response_tokens": count_tokens(stdout),
                    "translator_total_tokens": parse_codex_total_tokens(stdout + "\n" + stderr),
                    "translator_stderr": stderr[-2000:],
                }
            )

            if rc != 0:
                final_reason = "translator_error"
                previous_error = f"Translator failed with rc={rc}.\n{stderr[-4000:]}"
                attempt_records.append(attempt_record)
                continue

            parsed = extract_json_object(stdout)
            policy, notes = normalize_policy(parsed if parsed is not None else stdout, stdout)
            attempt_record["translator_notes"] = notes
            if policy is None:
                final_reason = "no_policy"
                previous_error = "No policy was returned. Return a complete version: 1 policy YAML."
                attempt_records.append(attempt_record)
                continue

            policy_path = policy_dir / f"attempt{attempt}.yaml"
            bin_path = policy_dir / f"attempt{attempt}.bin"
            policy_path.write_text(policy, encoding="utf-8")
            compile_result = compile_policy(actplane, policy_path, bin_path, args.compile_timeout)
            (compile_dir / f"attempt{attempt}.stdout").write_text(compile_result["stdout"], encoding="utf-8")
            (compile_dir / f"attempt{attempt}.stderr").write_text(compile_result["stderr"], encoding="utf-8")

            attempt_record.update(
                {
                    "policy_path": rel(policy_path),
                    "dsl_tokens": count_tokens(policy),
                    "dsl_chars": len(policy),
                    "compile_returncode": compile_result["returncode"],
                    "compile_elapsed_s": compile_result["elapsed_s"],
                    "compile_ok": compile_result["ok"],
                    "compile_error_category": compile_result["error_category"],
                    "binary_size": compile_result["binary_size"],
                }
            )
            attempt_records.append(attempt_record)

            if compile_result["ok"]:
                final_policy = policy
                final_compile = compile_result
                final_status = "compiled"
                final_reason = "compiled"
                shutil.copy2(policy_path, policy_dir / "policy.yaml")
                shutil.copy2(bin_path, policy_dir / "policy.bin")
                break

            final_reason = compile_result["error_category"] or "compiler_error"
            previous_error = (
                "The policy did not compile.\n"
                f"Error category: {final_reason}\n"
                f"stdout:\n{compile_result['stdout'][-3000:]}\n"
                f"stderr:\n{compile_result['stderr'][-3000:]}\n"
            )

        elapsed_item = time.monotonic() - start_item
        dsl_tokens = count_tokens(final_policy) if final_policy else None
        nl_tokens = item["nl_tokens"]
        record = {
            **item,
            "status": final_status,
            "final_reason": final_reason,
            "attempts": len(attempt_records),
            "retry_count": max(0, len(attempt_records) - 1),
            "duration_s": elapsed_item,
            "policy_path": rel(policy_dir / "policy.yaml") if final_policy else None,
            "binary_path": rel(policy_dir / "policy.bin") if final_policy else None,
            "binary_size": final_compile["binary_size"] if final_compile else None,
            "dsl_tokens": dsl_tokens,
            "dsl_chars": len(final_policy) if final_policy else None,
            "compression_ratio_dsl_over_nl": (dsl_tokens / nl_tokens) if dsl_tokens is not None and nl_tokens else None,
            "attempt_records": attempt_records,
        }
        append_jsonl(results_path, record)

    summarize_run(run_dir)
    return 0


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    frac = rank - lower
    return ordered[lower] * (1 - frac) + ordered[upper] * frac


def stats(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"n": 0, "mean": None, "p50": None, "p90": None, "p95": None, "min": None, "max": None}
    return {
        "n": len(values),
        "mean": sum(values) / len(values),
        "p50": percentile(values, 0.50),
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def summarize_run(run_dir: Path) -> dict[str, Any]:
    results = read_jsonl(run_dir / "results.jsonl")
    total = len(results)
    by_enf: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        by_enf[row.get("enforceability", "unknown")].append(row)

    coverage: dict[str, Any] = {
        "all": {
            "total": total,
            "compiled": sum(1 for row in results if row.get("status") == "compiled"),
        }
    }
    for enf, rows in sorted(by_enf.items()):
        coverage[enf] = {
            "total": len(rows),
            "compiled": sum(1 for row in rows if row.get("status") == "compiled"),
        }
    for bucket in coverage.values():
        total_bucket = bucket["total"]
        bucket["compile_rate"] = bucket["compiled"] / total_bucket if total_bucket else None

    compiled = [row for row in results if row.get("status") == "compiled"]
    retry_rows = [row for row in results if row.get("attempts", 0) > 1]
    failure_reasons = Counter(row.get("final_reason", "unknown") for row in results if row.get("status") != "compiled")

    token_stats = {
        "nl_tokens": stats([float(row["nl_tokens"]) for row in results if row.get("nl_tokens") is not None]),
        "dsl_tokens_compiled": stats([float(row["dsl_tokens"]) for row in compiled if row.get("dsl_tokens") is not None]),
        "compression_ratio_dsl_over_nl": stats(
            [float(row["compression_ratio_dsl_over_nl"]) for row in compiled if row.get("compression_ratio_dsl_over_nl") is not None]
        ),
        "translator_total_tokens": stats(
            [
                float(attempt["translator_total_tokens"])
                for row in results
                for attempt in row.get("attempt_records", [])
                if attempt.get("translator_total_tokens") is not None
            ]
        ),
    }

    complexity: dict[str, Any] = {}
    for enf, rows in sorted(by_enf.items()):
        compiled_rows = [row for row in rows if row.get("status") == "compiled"]
        complexity[enf] = {
            "dsl_tokens": stats([float(row["dsl_tokens"]) for row in compiled_rows if row.get("dsl_tokens") is not None]),
            "binary_size": stats([float(row["binary_size"]) for row in compiled_rows if row.get("binary_size") is not None]),
            "attempts": stats([float(row["attempts"]) for row in rows if row.get("attempts") is not None]),
        }

    summary = {
        "run_dir": rel(run_dir),
        "tokenizer": TOKENIZER_NAME,
        "coverage": coverage,
        "retry": {
            "total_with_retry": len(retry_rows),
            "retry_rate": len(retry_rows) / total if total else None,
            "mean_attempts_all": (sum(row.get("attempts", 0) for row in results) / total) if total else None,
            "mean_attempts_compiled": (sum(row.get("attempts", 0) for row in compiled) / len(compiled)) if compiled else None,
            "failure_reasons": dict(sorted(failure_reasons.items())),
        },
        "token_cost": token_stats,
        "rule_complexity": complexity,
    }
    write_json(run_dir / "summary.json", summary)
    write_metrics_csv(run_dir, results)
    write_summary_md(run_dir, summary)
    return summary


def fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def fmt_num(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, int):
        return str(value)
    if abs(value - round(value)) < 0.01:
        return str(int(round(value)))
    return f"{value:.2f}"


def write_summary_md(run_dir: Path, summary: dict[str, Any]) -> None:
    coverage = summary["coverage"]
    retry = summary["retry"]
    lines = [
        "# RQ1 Expressiveness Summary",
        "",
        f"Run: `{summary['run_dir']}`",
        f"Tokenizer: `{summary['tokenizer']}`",
        "",
        "## M1 Coverage",
        "",
        "| split | total | compiled | rate |",
        "|---|---:|---:|---:|",
    ]
    for key in ("all", "per_event", "cross_event"):
        bucket = coverage.get(key, {"total": 0, "compiled": 0, "compile_rate": None})
        lines.append(f"| {key} | {bucket['total']} | {bucket['compiled']} | {fmt_rate(bucket['compile_rate'])} |")

    lines.extend(
        [
            "",
            "## M2 Retry Rate",
            "",
            f"- Retry rate: {fmt_rate(retry['retry_rate'])}",
            f"- Mean attempts, all directives: {fmt_num(retry['mean_attempts_all'])}",
            f"- Mean attempts, compiled directives: {fmt_num(retry['mean_attempts_compiled'])}",
            f"- Failure reasons: `{json.dumps(retry['failure_reasons'], sort_keys=True)}`",
            "",
            "## M3 Token Cost",
            "",
            "| metric | n | mean | p50 | p90 | p95 | min | max |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for key, vals in summary["token_cost"].items():
        lines.append(
            f"| {key} | {vals['n']} | {fmt_num(vals['mean'])} | {fmt_num(vals['p50'])} | "
            f"{fmt_num(vals['p90'])} | {fmt_num(vals['p95'])} | {fmt_num(vals['min'])} | {fmt_num(vals['max'])} |"
        )

    lines.extend(["", "## M4 Rule Complexity", ""])
    for enf, vals in summary["rule_complexity"].items():
        lines.extend(
            [
                f"### {enf}",
                "",
                "| metric | n | mean | p50 | p90 | p95 | min | max |",
                "|---|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for metric in ("dsl_tokens", "binary_size", "attempts"):
            stat = vals[metric]
            lines.append(
                f"| {metric} | {stat['n']} | {fmt_num(stat['mean'])} | {fmt_num(stat['p50'])} | "
                f"{fmt_num(stat['p90'])} | {fmt_num(stat['p95'])} | {fmt_num(stat['min'])} | {fmt_num(stat['max'])} |"
            )
        lines.append("")

    (run_dir / "summary.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_metrics_csv(run_dir: Path, results: list[dict[str, Any]]) -> None:
    fields = [
        "uid",
        "repo",
        "statement_id",
        "enforceability",
        "status",
        "final_reason",
        "attempts",
        "retry_count",
        "nl_tokens",
        "dsl_tokens",
        "compression_ratio_dsl_over_nl",
        "binary_size",
        "translator_total_tokens",
        "duration_s",
        "policy_path",
    ]
    with (run_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in results:
            rendered = {field: row.get(field) for field in fields}
            totals = [
                attempt.get("translator_total_tokens")
                for attempt in row.get("attempt_records", [])
                if attempt.get("translator_total_tokens") is not None
            ]
            rendered["translator_total_tokens"] = sum(totals) if totals else None
            writer.writerow(rendered)


def command_summarize(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    summary = summarize_run(run_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    manifest = sub.add_parser("manifest", help="write the frozen 607-directive manifest")
    manifest.add_argument("--corpus-root", default=str(CORPUS_ROOT))
    manifest.add_argument("--out", default=str(RQ_DIR / "directives.jsonl"))
    manifest.add_argument("--strict", action="store_true", help="exit non-zero if counts differ from 392/215")
    manifest.set_defaults(func=command_manifest)

    translate = sub.add_parser("translate", help="translate, compile, and summarize policies")
    translate.add_argument("--corpus-root", default=str(CORPUS_ROOT))
    translate.add_argument("--run-dir", default=None)
    translate.add_argument("--limit", type=int, default=None)
    translate.add_argument("--resume", action="store_true")
    translate.add_argument("--translator", choices=("codex", "cmd"), default="codex")
    translate.add_argument("--translator-cmd", default=None)
    translate.add_argument(
        "--codex-config",
        action="append",
        default=[],
        help="Codex config override passed as `-c key=value`; repeat for multiple overrides",
    )
    translate.add_argument(
        "--codex-arg",
        action="append",
        default=[],
        help="extra argument passed to `codex exec` before the prompt; repeat for multiple args",
    )
    translate.add_argument("--max-attempts", type=int, default=3)
    translate.add_argument("--translator-timeout", type=float, default=900.0)
    translate.add_argument("--compile-timeout", type=float, default=30.0)
    translate.add_argument("--actplane", default=None)
    translate.add_argument("--no-embed-context", action="store_true")
    translate.add_argument("--max-context-chars", type=int, default=12000)
    translate.add_argument("--tree-files", type=int, default=120)
    translate.set_defaults(func=command_translate)

    summarize = sub.add_parser("summarize", help="summarize an existing run")
    summarize.add_argument("--run-dir", required=True)
    summarize.set_defaults(func=command_summarize)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
