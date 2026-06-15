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
RQ2_QWEN_SELECTED = ROOT / "docs/artifact/rq2-qwen-primary/selected_runner_results.txt"
RQ2_DEEPSEEK_DIR = ROOT / "docs/eval_runs/full/deepseek_rq1_20260607T193612Z_v4_pro"
RQ3_MICRO = ROOT / "docs/rq2-performance/results/rq2-micro-2026-06-02T-osdi"
RQ3_MACRO = ROOT / "docs/rq2-performance/results/rq2-macro-2026-06-02T-osdi-v2"
RQ4_LEDGER = ROOT / "docs/artifact/rq4_octobench_ledger.json"
RQ4_SUMMARY = ROOT / "docs/artifact/rq4_octobench_summary.json"
RQ5_LEDGER = ROOT / "docs/artifact/rq5_openagentsafety_ledger.json"
RQ5_SUMMARY = ROOT / "docs/artifact/rq5_openagentsafety_summary.json"
RQ2_JUDGE_DIR = "trajectory_judges_deepseek_deepseek_v4_pro_guardrail_response"

STALE_ARTIFACT_PATHS = [
    ROOT / "docs/tmp",
    ROOT / "docs/OctoBench/data/core-results-old",
    ROOT / "docs/OctoBench/data/selected_cases.jsonl",
    ROOT / "docs/OctoBench/data/selected_cases_20.jsonl",
    ROOT / "docs/OctoBench/data/selected_cases_30.jsonl",
    ROOT / "docs/OctoBench/data/selected_cases_extra10.jsonl",
    ROOT / "docs/OctoBench/data/selected_tuned_10.jsonl",
    ROOT / "docs/OpenAgentSafety/data/archive",
    ROOT / "docs/OpenAgentSafety/policies/archive",
    ROOT / "docs/OpenAgentSafety/policies/moved-out",
]
STALE_NAME_MARKERS = [
    "one_trace_tuning",
    "visible10_smoke",
]


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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    require(path, "required JSONL artifact is missing")
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def artifact_path(value: str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def verify_artifact_hygiene() -> None:
    stale = [path.relative_to(ROOT) for path in STALE_ARTIFACT_PATHS if path.exists()]
    corpus_root = ROOT / "docs/corpus-test"
    if corpus_root.exists():
        for path in corpus_root.rglob("results"):
            if path.is_dir():
                stale.append(path.relative_to(ROOT))
    for path in (ROOT / "docs").rglob("*"):
        rel = path.relative_to(ROOT)
        text = str(rel)
        if any(marker in text for marker in STALE_NAME_MARKERS):
            stale.append(rel)
    if stale:
        sample = ", ".join(str(path) for path in stale[:8])
        raise SystemExit(f"stale scratch artifact paths remain: {sample}")
    print("Artifact hygiene")
    print("- no stale scratch/tuning/archive paths found")


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
        path = Path(line.split("\t")[-1])
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


def verify_rq2() -> int:
    qwen = summarize_rq2_selected(RQ2_QWEN_SELECTED, "trajectory_judges_llama_cpp_guardrail_response")

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
    print(f"- source: {RQ2_QWEN_SELECTED.relative_to(ROOT)}")

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
    ledger = load_json(RQ4_LEDGER)
    selected_ids = [
        line.strip()
        for line in (ROOT / "docs/OctoBench/data/selected_cases_21.ids").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(selected_ids) != int(summary["selected_tasks"]):
        raise SystemExit(f"RQ4 selected task count mismatch: expected {summary['selected_tasks']}, got {len(selected_ids)}")
    if count_jsonl(ROOT / "docs/OctoBench/data/selected_cases_21.jsonl") != int(summary["selected_tasks"]):
        raise SystemExit("RQ4 selected_cases_21.jsonl row count mismatch")

    manifest_rows = load_jsonl(ROOT / "docs/OctoBench/data/policy_manifest.jsonl")
    if len(manifest_rows) != int(summary["selected_tasks"]):
        raise SystemExit("RQ4 policy_manifest.jsonl row count mismatch")
    manifest_ids = [str(row["case_id"]) for row in manifest_rows]
    if manifest_ids != selected_ids:
        raise SystemExit("RQ4 policy_manifest.jsonl IDs do not match selected_cases_21.ids")

    rows = ledger.get("rows", [])
    if ledger.get("schema") != "actplane.rq4.octobench.ledger.v1":
        raise SystemExit("RQ4 ledger schema mismatch")
    if int(ledger.get("selected_count", -1)) != int(summary["selected_tasks"]) or len(rows) != int(summary["selected_tasks"]):
        raise SystemExit("RQ4 ledger selected task count mismatch")
    ledger_ids = [str(row["case_id"]) for row in rows]
    if ledger_ids != selected_ids:
        raise SystemExit("RQ4 ledger IDs do not match selected_cases_21.ids")

    rule_count = 0
    for row in rows:
        for key in ["canonical_policy", "tool_regex_policy", "actplane_feedback_policy"]:
            path = artifact_path(row.get(key))
            if path is None:
                raise SystemExit(f"RQ4 ledger row {row.get('case_id')} missing {key}")
            require(path, f"RQ4 ledger path {key} is missing")
        legacy = artifact_path(row.get("actplane_legacy_policy"))
        if legacy is not None:
            require(legacy, "RQ4 optional legacy policy listed in ledger is missing")
        policy = artifact_path(row["actplane_feedback_policy"])
        row_rules = count_policy_rules([policy])
        if row_rules != int(row["actplane_feedback_rule_count"]):
            raise SystemExit(
                f"RQ4 rule count mismatch for {row['case_id']}: "
                f"ledger has {row['actplane_feedback_rule_count']}, counted {row_rules}"
            )
        if row.get("reward_provenance") != "aggregate_summary_only" or row.get("per_task_reward_available") is not False:
            raise SystemExit(f"RQ4 ledger row {row['case_id']} has ambiguous reward provenance")
        rule_count += row_rules
    if int(ledger.get("actplane_feedback_rule_count", -1)) != rule_count:
        raise SystemExit("RQ4 ledger aggregate rule count mismatch")
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
    print(f"- ledger: {RQ4_LEDGER.relative_to(ROOT)}")
    print("- source: docs/OctoBench/data/selected_cases_21.*, policy_manifest.jsonl, and docs/OctoBench/policies/actplane-feedback/")
    return 0


def verify_rq5() -> int:
    summary = load_json(RQ5_SUMMARY)
    ledger = load_json(RQ5_LEDGER)
    manifest = load_json(ROOT / "docs/OpenAgentSafety/data/remaining_attempt0_description_manifest.json")
    final_manifest = load_json(ROOT / "docs/OpenAgentSafety/data/os_effect_blockable_50.json")
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

    rows = ledger.get("rows", [])
    if ledger.get("schema") != "actplane.rq5.openagentsafety.ledger.v1":
        raise SystemExit("RQ5 ledger schema mismatch")
    if int(ledger.get("total_tasks", -1)) != int(counts["total_tasks"]) or len(rows) != int(counts["total_tasks"]):
        raise SystemExit("RQ5 ledger total task count mismatch")
    task_ids = [str(row["task_id"]) for row in rows]
    if len(task_ids) != len(set(task_ids)):
        raise SystemExit("RQ5 ledger contains duplicate task IDs")

    final_rows = [row for row in rows if row.get("policy_group") == "final_blockable_50"]
    attempt0_rows = [row for row in rows if row.get("policy_group") == "remaining_attempt0_description"]
    if len(final_rows) != int(inventory["final_blockable_policies"]):
        raise SystemExit("RQ5 ledger final blockable count mismatch")
    if len(attempt0_rows) != int(inventory["attempt0_generated_policies"]):
        raise SystemExit("RQ5 ledger attempt0 count mismatch")
    if sum(1 for row in attempt0_rows if row.get("is_noop")) != int(inventory["attempt0_noop_policies"]):
        raise SystemExit("RQ5 ledger attempt0 no-op count mismatch")

    final_ids = sorted(str(item["task_id"]) for item in final_manifest["cases"])
    attempt0_ids = sorted(str(item["task_id"]) for item in manifest["cases"])
    if sorted(str(row["task_id"]) for row in final_rows) != final_ids:
        raise SystemExit("RQ5 ledger final task IDs do not match os_effect_blockable_50.json")
    if sorted(str(row["task_id"]) for row in attempt0_rows) != attempt0_ids:
        raise SystemExit("RQ5 ledger attempt0 task IDs do not match remaining manifest")
    for row in rows:
        policy = artifact_path(row.get("policy"))
        if policy is None:
            raise SystemExit(f"RQ5 ledger row {row.get('task_id')} is missing policy path")
        require(policy, "RQ5 ledger policy path is missing")
        if row.get("outcome_provenance") != "aggregate_summary_only" or row.get("per_task_outcome_available") is not False:
            raise SystemExit(f"RQ5 ledger row {row['task_id']} has ambiguous outcome provenance")

    final_policies = len(list((ROOT / "docs/OpenAgentSafety/policies/actplane").glob("*.yaml")))
    attempt0_policies = len(list((ROOT / "docs/OpenAgentSafety/policies/remaining_attempts/attempt0-description").glob("*.yaml")))
    if final_policies != int(inventory["final_blockable_policies"]):
        raise SystemExit(f"RQ5 final policy files mismatch: expected {inventory['final_blockable_policies']}, got {final_policies}")
    if attempt0_policies != int(inventory["attempt0_generated_policies"]):
        raise SystemExit(f"RQ5 attempt0 policy files mismatch: expected {inventory['attempt0_generated_policies']}, got {attempt0_policies}")
    nontrivial = len(final_rows) + sum(1 for row in attempt0_rows if not row.get("is_noop"))
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
    print(f"- ledger: {RQ5_LEDGER.relative_to(ROOT)}")
    print("- source: docs/OpenAgentSafety/data/*.json and docs/OpenAgentSafety/policies/")
    print("- note: full OpenAgentSafety run logs are not tracked on artifact-ready; see docs/ARTIFACT.md.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rq", choices=["rq1", "rq2", "rq3", "rq4", "rq5", "all"])
    args = parser.parse_args(argv)

    if args.rq == "all":
        verify_artifact_hygiene()
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
