#!/usr/bin/env python3
"""Audit the frozen OpenAgentSafety policy inventory without outcome claims.

This script deliberately reports syntax compilation and observable policy
structure.  It does not reconstruct per-task outcomes or grade policy meaning.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path


ACTION_RE = re.compile(r"^\s+(?:kill|notify)\s+(exec|open|read|write|unlink|connect)\b")
COMPILE_RE = re.compile(r"compiled (\d+) rule\(s\)")
SERVICE_MARKERS = ("gitlab", "owncloud", "plane")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit frozen OpenAgentSafety policies and compile them with ActPlane."
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        required=True,
        help="Root containing docs/OpenAgentSafety and docs/artifact from artifact-ready",
    )
    parser.add_argument(
        "--compiler", type=Path, required=True, help="ActPlane CLI binary to use"
    )
    parser.add_argument(
        "--official-task-root",
        type=Path,
        help="Optional flat directory containing <task-id>.md from the frozen OAS commit",
    )
    parser.add_argument("--summary-out", type=Path, required=True)
    parser.add_argument("--rows-out", type=Path, required=True)
    parser.add_argument("--expected-total", type=int, default=361)
    parser.add_argument("--expected-description", type=int, default=311)
    parser.add_argument("--expected-final", type=int, default=50)
    parser.add_argument("--expected-noop", type=int, default=58)
    return parser.parse_args()


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def service_membership(batch_root: Path) -> dict[str, set[str]]:
    membership: dict[str, set[str]] = defaultdict(set)
    for path in sorted(batch_root.glob("*.json")):
        # Match only the manifest basename.  Parent paths such as
        # "actplane-research" must not accidentally classify every task as Plane.
        markers = {marker for marker in SERVICE_MARKERS if marker in path.name.lower()}
        if not markers:
            continue
        payload = load_json(path)
        assert isinstance(payload, dict)
        for case in payload.get("cases", []):
            membership[case["task_id"]].update(markers)
    return membership


def policy_actions(path: Path) -> Counter[str]:
    actions: Counter[str] = Counter()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            match = ACTION_RE.match(line)
            if match:
                actions[match.group(1)] += 1
    return actions


def compile_policy(compiler: Path, policy: Path, output: Path) -> tuple[int, int | None, str]:
    completed = subprocess.run(
        [str(compiler), "--policy", str(policy), "compile", "--out", str(output), "--force"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    match = COMPILE_RE.search(completed.stdout)
    return completed.returncode, int(match.group(1)) if match else None, completed.stdout.strip()


def main() -> int:
    args = parse_args()
    artifact_root = args.artifact_root.resolve()
    compiler = args.compiler.resolve()
    oas_root = artifact_root / "docs" / "OpenAgentSafety"
    manifest_path = oas_root / "data" / "remaining_attempt0_description_manifest.json"
    ledger_path = artifact_root / "docs" / "artifact" / "rq5_openagentsafety_ledger.json"
    batch_root = oas_root / "data" / "remaining_attempt0_batches"
    final_root = oas_root / "policies" / "actplane"
    description_root = oas_root / "policies" / "remaining_attempts" / "attempt0-description"

    manifest = load_json(manifest_path)
    ledger = load_json(ledger_path)
    assert isinstance(manifest, dict) and isinstance(ledger, dict)
    description_cases = {case["task_id"]: case for case in manifest["cases"]}
    ledger_rows = {row["task_id"]: row for row in ledger["rows"]}
    services = service_membership(batch_root)

    final_policies = sorted(final_root.glob("*.yaml"))
    description_policies = sorted(description_root.glob("*.yaml"))
    policy_specs: list[tuple[str, Path, bool]] = []
    policy_specs.extend(("final50", path, False) for path in final_policies)
    for path in description_policies:
        task_id = path.stem
        policy_specs.append(
            ("description311", path, bool(description_cases[task_id]["is_noop"]))
        )

    errors: list[str] = []
    expected = {
        "ledger rows": (len(ledger_rows), args.expected_total),
        "all policies": (len(policy_specs), args.expected_total),
        "description policies": (len(description_policies), args.expected_description),
        "final policies": (len(final_policies), args.expected_final),
        "description no-op policies": (
            sum(bool(case["is_noop"]) for case in description_cases.values()),
            args.expected_noop,
        ),
    }
    for label, (actual, wanted) in expected.items():
        if actual != wanted:
            errors.append(f"{label}: expected {wanted}, found {actual}")
    if set(ledger_rows) != {path.stem for _, path, _ in policy_specs}:
        errors.append("ledger task IDs do not exactly match policy filenames")

    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="actplane-oas-audit-") as temp_dir:
        output = Path(temp_dir) / "policy.bin"
        for group, policy, is_noop in policy_specs:
            actions = policy_actions(policy)
            task_id = policy.stem
            rc, lowered_rules, compile_output = compile_policy(compiler, policy, output)
            if rc != 0:
                errors.append(f"compile failed for {task_id}: {compile_output}")
            task_path = (
                args.official_task_root / f"{task_id}.md"
                if args.official_task_root
                else None
            )
            rows.append(
                {
                    "task_id": task_id,
                    "policy_group": group,
                    "is_noop": int(is_noop),
                    "service_markers": ",".join(sorted(services.get(task_id, set()))),
                    "official_task_available": int(bool(task_path and task_path.is_file())),
                    "compile_rc": rc,
                    "lowered_rules": lowered_rules if lowered_rules is not None else "",
                    "exec_rules": actions["exec"],
                    "connect_rules": actions["connect"],
                    "open_or_read_rules": actions["open"] + actions["read"],
                    "write_rules": actions["write"],
                    "unlink_rules": actions["unlink"],
                    "policy_sha256": sha256(policy),
                    "official_task_sha256": sha256(task_path)
                    if task_path and task_path.is_file()
                    else "",
                }
            )

    service_rows = [row for row in rows if row["service_markers"]]
    description_rows = [row for row in rows if row["policy_group"] == "description311"]
    nontrivial_description = [row for row in description_rows if not row["is_noop"]]
    official_available = sum(row["official_task_available"] for row in rows)
    summary = {
        "claim_boundary": {
            "does_establish": [
                "frozen policy inventory counts",
                "syntax compilation with the identified ActPlane binary",
                "syntactic policy action coverage",
            ],
            "does_not_establish": [
                "semantic policy correctness",
                "per-task prevention or end-to-end outcome",
                "held-out generalization",
                "an independent baseline comparison",
            ],
        },
        "inputs": {
            "artifact_root": str(artifact_root),
            "compiler": str(compiler),
            "compiler_sha256": sha256(compiler),
            "manifest_sha256": sha256(manifest_path),
            "ledger_sha256": sha256(ledger_path),
            "official_task_root": str(args.official_task_root.resolve())
            if args.official_task_root
            else None,
        },
        "inventory": {
            "total_policies": len(rows),
            "final_policies": len(final_policies),
            "description_only_policies": len(description_rows),
            "description_only_nontrivial": len(nontrivial_description),
            "description_only_noop": len(description_rows) - len(nontrivial_description),
            "official_task_descriptions_available": official_available,
            "official_task_descriptions_missing": len(rows) - official_available
            if args.official_task_root
            else None,
        },
        "compilation": {
            "success": sum(row["compile_rc"] == 0 for row in rows),
            "failure": sum(row["compile_rc"] != 0 for row in rows),
            "lowered_rules_nontrivial_description": sum(
                int(row["lowered_rules"]) for row in nontrivial_description
            ),
            "lowered_rules_noop_description": sum(
                int(row["lowered_rules"]) for row in description_rows if row["is_noop"]
            ),
        },
        "service_manifest_subset": {
            "definition": (
                "task ID appears in a frozen batch manifest whose basename contains "
                "gitlab, owncloud, or plane"
            ),
            "tasks": len(service_rows),
            "with_connect_rule": sum(row["connect_rules"] > 0 for row in service_rows),
            "with_exec_rule": sum(row["exec_rules"] > 0 for row in service_rows),
            "with_neither_connect_nor_exec": sum(
                row["connect_rules"] == 0 and row["exec_rules"] == 0
                for row in service_rows
            ),
            "action_rule_totals": {
                name: sum(int(row[name]) for row in service_rows)
                for name in (
                    "connect_rules",
                    "exec_rules",
                    "open_or_read_rules",
                    "write_rules",
                    "unlink_rules",
                )
            },
        },
        "errors": errors,
    }

    args.rows_out.parent.mkdir(parents=True, exist_ok=True)
    with args.rows_out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)
    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    with args.summary_out.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
