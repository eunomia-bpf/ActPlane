#!/usr/bin/env python3
"""Verify paper-facing ActPlane artifact summaries.

The default artifact targets do not regenerate policies. They read frozen
inputs/results committed on the artifact branch and recompute the tables that
the paper cites.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RQ1_DIR = ROOT / "docs/eval_runs/rq1-expressiveness/full-607-subagents"
RQ2_QWEN_STATS = ROOT / "docs/tmp/rq1/latest_existing_stats/current_latest_stats_20260607T191939Z.txt"
RQ2_QWEN_TOOL_IFC = ROOT / "docs/eval_runs/full/20260607_current_full_after_trace_harness_fix/selected_runner_results.txt"
RQ2_DEEPSEEK_DIR = ROOT / "docs/eval_runs/full/deepseek_rq1_20260607T193612Z_v4_pro"
RQ3_MICRO = ROOT / "docs/rq2-performance/results/rq2-micro-2026-06-02T-osdi"
RQ3_MACRO = ROOT / "docs/rq2-performance/results/rq2-macro-2026-06-02T-osdi-v2"
RQ4_SUMMARY = ROOT / "docs/artifact/rq4_octobench_summary.json"
RQ5_SUMMARY = ROOT / "docs/artifact/rq5_openagentsafety_summary.json"
RQ2_JUDGE_DIR = "trajectory_judges_deepseek_deepseek_v4_pro_guardrail_response"


def require(path: Path, hint: str) -> None:
    if not path.exists():
        rel = path.relative_to(ROOT)
        raise SystemExit(
            f"missing {rel}\n"
            f"{hint}\n"
            "If you are on master, switch to the artifact-ready branch or fetch "
            "the raw backup listed in docs/ARTIFACT.md."
        )


def load_json(path: Path) -> Any:
    require(path, "required artifact file is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def verify_rq1() -> int:
    summary = load_json(RQ1_DIR / "summary.json")
    coverage = summary["coverage"]
    retry = summary["retry"]

    expected = {
        "all": (607, 607),
        "per_event": (392, 392),
        "cross_event": (215, 215),
    }
    for key, (total, compiled) in expected.items():
        got = coverage[key]
        if got["total"] != total or got["compiled"] != compiled:
            raise SystemExit(f"RQ1 {key} mismatch: expected {compiled}/{total}, got {got}")

    print("RQ1 expressiveness")
    print(f"- all directives compiled: {coverage['all']['compiled']}/{coverage['all']['total']}")
    print(
        f"- per-event: {coverage['per_event']['compiled']}/{coverage['per_event']['total']}; "
        f"cross-event: {coverage['cross_event']['compiled']}/{coverage['cross_event']['total']}"
    )
    print(f"- retry rate: {100 * retry['retry_rate']:.1f}%")
    print(f"- source: {RQ1_DIR.relative_to(ROOT)}")
    return 0


def load_summarizer_module():
    path = ROOT / "docs/eval_scripts/summarize_agent_sdk_results.py"
    require(path, "RQ2 summarizer is missing")
    spec = importlib.util.spec_from_file_location("actplane_rq2_summarizer", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def summarize_rq2_selected(selected: Path, judge_dir_name: str) -> dict[str, dict[str, Any]]:
    require(selected, "RQ2 selected runner list is missing")
    summarizer = load_summarizer_module()
    paths = []
    for line in selected.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path = Path(line)
        paths.append(path if path.is_absolute() else ROOT / path)
    results = []
    for path in summarizer.iter_result_files(paths):
        item = summarizer.load_json(path)
        if item and item.get("system") in summarizer.SYSTEMS:
            results.append(item)
    if not results:
        raise SystemExit("RQ2 selected list did not resolve to runner results")

    results = summarizer.select_latest(results)
    results = [item for item in results if summarizer.is_scorable_result(item)]
    rows, missing = summarizer.load_judged_rows(results, judge_dir_name=judge_dir_name)
    if missing:
        raise SystemExit(f"RQ2 missing {len(missing)} judge files; first missing: {missing[0]}")

    by_system: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_system[str(row["result"].get("system") or "unknown")].append(row)
    summary = {
        system: summarizer.summarize_system(items)
        for system, items in by_system.items()
        if items
    }
    return summary


def parse_qwen_table(path: Path) -> dict[str, dict[str, int]]:
    require(path, "RQ2 primary Qwen summary is missing")
    out: dict[str, dict[str, int]] = {}
    row_re = re.compile(
        r"^\| (?P<system>[^|]+) \| (?P<correct>\d+)/(?P<scored>\d+) "
        r"\([^)]*\) \| (?P<tp>\d+) \| (?P<tn>\d+) \| (?P<fp>\d+) \| "
        r"(?P<fn>\d+) \| (?P<unclear>\d+) \| (?P<judged>\d+) \|$"
    )
    for line in path.read_text(encoding="utf-8").splitlines():
        match = row_re.match(line.strip())
        if not match:
            continue
        out[match.group("system")] = {
            key: int(match.group(key))
            for key in ["correct", "scored", "tp", "tn", "fp", "fn", "unclear", "judged"]
        }
    if not out:
        raise SystemExit(f"RQ2 could not parse summary table from {path.relative_to(ROOT)}")
    return out


def verify_rq2() -> int:
    qwen = parse_qwen_table(RQ2_QWEN_STATS)
    qwen_tool_ifc = summarize_rq2_selected(RQ2_QWEN_TOOL_IFC, "trajectory_judges_llama_cpp_guardrail_response")
    if "tool-ifc" not in qwen_tool_ifc:
        raise SystemExit("RQ2 primary Qwen summary is missing tool-ifc/FIDES rows")
    qwen["tool-ifc"] = qwen_tool_ifc["tool-ifc"]

    expected_qwen = {
        "prompt-filter": (92, 190, 44, 48, 28, 70, 0, 190),
        "tool-regex": (86, 190, 38, 48, 28, 76, 0, 190),
        "tool-ifc": (93, 190, 41, 52, 24, 73, 0, 190),
        "actplane": (144, 190, 86, 58, 18, 28, 0, 190),
        "actplane-opaque": (102, 190, 27, 75, 1, 87, 0, 190),
    }
    for system, expected_tuple in expected_qwen.items():
        item = qwen.get(system)
        if item is None:
            raise SystemExit(f"RQ2 primary Qwen missing system {system}")
        got = (
            item["correct"],
            item["scored"],
            item["tp"],
            item["tn"],
            item["fp"],
            item["fn"],
            item["unclear"],
            item["judged"],
        )
        if got != expected_tuple:
            raise SystemExit(f"RQ2 primary Qwen {system} mismatch: expected {expected_tuple}, got {got}")

    selected = RQ2_DEEPSEEK_DIR / "selected_runner_results.txt"
    require(RQ2_DEEPSEEK_DIR / "rq2_data_summary.md", "RQ2 DeepSeek data summary is missing")
    summary = summarize_rq2_selected(selected, RQ2_JUDGE_DIR)
    expected = {
        "prompt-filter": (93, 177, 22, 71, 5, 79, 13, 190),
        "tool-regex": (80, 183, 32, 48, 28, 75, 7, 190),
        "tool-ifc": (87, 189, 38, 49, 27, 75, 1, 190),
        "actplane": (144, 186, 82, 62, 14, 28, 4, 190),
        "actplane-opaque": (108, 175, 34, 74, 1, 66, 15, 190),
    }
    for system, expected_tuple in expected.items():
        item = summary.get(system)
        if item is None:
            raise SystemExit(f"RQ2 missing system {system}")
        got = (
            item["correct"],
            item["scored"],
            item["tp"],
            item["tn"],
            item["fp"],
            item["fn"],
            item["unclear"],
            item["judged"],
        )
        if got != expected_tuple:
            raise SystemExit(f"RQ2 DeepSeek {system} mismatch: expected {expected_tuple}, got {got}")

    summarizer = load_summarizer_module()
    print("RQ2 decision compliance, primary Qwen3.6-27B setting")
    for system in summarizer.SYSTEMS:
        item = qwen[system]
        display = summarizer.DISPLAY_NAMES.get(system, system)
        print(
            f"- {display}: {item['correct']}/{item['scored']} "
            f"({100 * item['correct'] / item['scored']:.1f}%), "
            f"TP={item['tp']} TN={item['tn']} FP={item['fp']} FN={item['fn']}"
        )
    print(f"- source: {RQ2_QWEN_STATS.relative_to(ROOT)}")

    print("RQ2 decision compliance, DeepSeek-Pro V4 replication")
    for system in summarizer.SYSTEMS:
        item = summary[system]
        display = summarizer.DISPLAY_NAMES.get(system, system)
        print(
            f"- {display}: {item['correct']}/{item['scored']} "
            f"({100 * item['correct'] / item['scored']:.1f}%), "
            f"TP={item['tp']} TN={item['tn']} FP={item['fp']} FN={item['fn']} "
            f"unclear={item['unclear']}"
        )
    print(f"- source: {RQ2_DEEPSEEK_DIR.relative_to(ROOT)}")
    return 0


def verify_rq3() -> int:
    micro = load_json(RQ3_MICRO / "aggregate.json")
    macro = load_json(RQ3_MACRO / "aggregate.json")
    require(RQ3_MICRO / "metadata.json", "RQ3 micro metadata is missing")
    require(RQ3_MACRO / "metadata.json", "RQ3 macro metadata is missing")

    by_micro = {(row["config"], row["op"]): row for row in micro}
    by_macro = {(row["config"], row["workload"]): row for row in macro}
    for key in [("ap-32", "open"), ("ap-32", "write"), ("ap-32", "connect"), ("ap-32", "fork"), ("ap-32", "exec")]:
        if key not in by_micro:
            raise SystemExit(f"RQ3 micro missing {key}")
    for key in [("ap-32", "agent-trace"), ("ap-32", "linux-build")]:
        if key not in by_macro:
            raise SystemExit(f"RQ3 macro missing {key}")

    agent_trace = by_macro[("ap-32", "agent-trace")]
    linux_build = by_macro[("ap-32", "linux-build")]

    print("RQ3 performance")
    print("- ap-32 microbenchmark p50 overheads:")
    for op in ["open", "write", "connect", "fork", "exec"]:
        row = by_micro[("ap-32", op)]
        print(f"  - {op}: {row['overhead_p50_ns_pct']:.2f}%")
    print(
        f"- agent-trace elapsed overhead: {agent_trace['elapsed_overhead_pct']:.1f}% "
        f"(median {agent_trace['median_elapsed_s']}s)"
    )
    print(
        f"- linux-build elapsed overhead: {linux_build['elapsed_overhead_pct']:.1f}% "
        f"(median {linux_build['median_elapsed_s']}s)"
    )
    print(f"- micro source: {RQ3_MICRO.relative_to(ROOT)}")
    print(f"- macro source: {RQ3_MACRO.relative_to(ROOT)}")
    return 0


def count_jsonl(path: Path) -> int:
    require(path, "required JSONL artifact is missing")
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def count_policy_rules(policy_paths: list[Path]) -> int:
    total = 0
    for path in policy_paths:
        require(path, "required policy file is missing")
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.match(r"\s*rule\s+", line):
                total += 1
    return total


def verify_rq4() -> int:
    summary = load_json(RQ4_SUMMARY)
    selected_ids = [
        line.strip()
        for line in (ROOT / "docs/OctoBench/data/selected_cases_21.ids").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(selected_ids) != int(summary["selected_tasks"]):
        raise SystemExit(f"RQ4 selected task count mismatch: expected {summary['selected_tasks']}, got {len(selected_ids)}")
    if count_jsonl(ROOT / "docs/OctoBench/data/selected_cases_21.jsonl") != int(summary["selected_tasks"]):
        raise SystemExit("RQ4 selected_cases_21.jsonl row count mismatch")
    policy_root = ROOT / "docs/OctoBench/policies/actplane-feedback"
    rule_count = count_policy_rules([policy_root / f"{case_id}.yaml" for case_id in selected_ids])
    if rule_count != int(summary["dsl_rules"]):
        raise SystemExit(f"RQ4 DSL rule count mismatch: expected {summary['dsl_rules']}, got {rule_count}")

    conditions = summary["conditions"]
    print("RQ4 OctoBench summary")
    print(f"- selected tasks: {summary['selected_tasks']}; DSL rules: {summary['dsl_rules']}")
    print(
        "- official reward: "
        f"baseline={conditions['baseline']['official_reward']:.2f}, "
        f"hooks={conditions['claude_code_hooks']['official_reward']:.2f}, "
        f"actplane={conditions['actplane']['official_reward']:.2f}"
    )
    print(f"- runtime deltas submitted: {summary['runtime_deltas']}")
    print("- source: docs/OctoBench/data/selected_cases_21.* and docs/OctoBench/policies/actplane-feedback/")
    return 0


def verify_rq5() -> int:
    summary = load_json(RQ5_SUMMARY)
    manifest = load_json(ROOT / "docs/OpenAgentSafety/data/remaining_attempt0_description_manifest.json")
    counts = summary["outcome_counts"]
    inventory = summary["policy_inventory"]

    expected_total = (
        int(counts["actplane_prevented"])
        + int(counts["actplane_missed"])
        + int(counts["actplane_safe_or_refused"])
        + int(counts["actplane_noop"])
    )
    if expected_total != int(counts["total_tasks"]):
        raise SystemExit(f"RQ5 outcome counts do not sum to {counts['total_tasks']}: got {expected_total}")
    if int(manifest["tasks_total"]) != int(counts["total_tasks"]):
        raise SystemExit("RQ5 task total mismatch")
    if int(manifest["final_50_excluded"]) != int(inventory["final_blockable_policies"]):
        raise SystemExit("RQ5 final blockable policy count mismatch")
    if int(manifest["noop_policies"]) != int(inventory["attempt0_noop_policies"]):
        raise SystemExit("RQ5 no-op policy count mismatch")
    final_policies = len(list((ROOT / "docs/OpenAgentSafety/policies/actplane").glob("*.yaml")))
    attempt0_policies = len(list((ROOT / "docs/OpenAgentSafety/policies/remaining_attempts/attempt0-description").glob("*.yaml")))
    if final_policies != int(inventory["final_blockable_policies"]):
        raise SystemExit(f"RQ5 final policy files mismatch: expected {inventory['final_blockable_policies']}, got {final_policies}")
    if attempt0_policies != int(inventory["attempt0_generated_policies"]):
        raise SystemExit(f"RQ5 attempt0 policy files mismatch: expected {inventory['attempt0_generated_policies']}, got {attempt0_policies}")
    nontrivial = final_policies + attempt0_policies - int(inventory["attempt0_noop_policies"])
    if nontrivial != int(inventory["nontrivial_policies"]):
        raise SystemExit(f"RQ5 nontrivial policy count mismatch: expected {inventory['nontrivial_policies']}, got {nontrivial}")

    prevention = 100 * int(counts["actplane_prevented"]) / int(counts["baseline_unsafe"])
    print("RQ5 OpenAgentSafety summary")
    print(f"- tasks: {counts['total_tasks']}; baseline unsafe: {counts['baseline_unsafe']}")
    print(
        f"- prevented: {counts['actplane_prevented']}; missed: {counts['actplane_missed']}; "
        f"prevention rate: {prevention:.1f}%"
    )
    print(
        f"- policy inventory: {inventory['nontrivial_policies']} nontrivial, "
        f"{inventory['attempt0_noop_policies']} no-op"
    )
    print("- source: docs/OpenAgentSafety/data/remaining_attempt0_description_manifest.json")
    print("- note: full OpenAgentSafety run logs are not tracked on artifact-ready; see docs/ARTIFACT.md.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rq", choices=["rq1", "rq2", "rq3", "rq4", "rq5", "all"])
    args = parser.parse_args(argv)

    if args.rq in {"rq1", "all"}:
        verify_rq1()
    if args.rq in {"rq2", "all"}:
        verify_rq2()
    if args.rq in {"rq3", "all"}:
        verify_rq3()
    if args.rq in {"rq4", "all"}:
        verify_rq4()
    if args.rq in {"rq5", "all"}:
        verify_rq5()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
