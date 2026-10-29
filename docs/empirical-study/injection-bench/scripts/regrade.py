"""Independently grade terminal cells without rerunning agents or changing ASR.

Run only in the Workspace. Existing task state and original records are frozen
under run/grading before the official unprivileged evaluator is invoked.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import traceback

from benchmark_runner import UPSTREAM, independent_grade, load_tasks
from repoguard.scoring.semantics import score_run_from_log


TERMINAL = {"complete", "failed"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, value):
    data = json.dumps(value, ensure_ascii=False, indent=2).encode()
    fd, name = tempfile.mkstemp(prefix=".regrade-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def freeze(path, data):
    """Preserve the first original bytes and reject conflicting ASR snapshots."""
    try:
        with path.open("xb") as output:
            output.write(data)
    except FileExistsError:
        if path.read_bytes() != data:
            raise ValueError(f"frozen evidence differs: {path.name}")


def trusted_root(task, case, grading):
    spec = grading / "spec.json"
    if spec.exists():
        for path in (grading, spec):
            info = path.lstat()
            if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("grading specification is not protected and root-owned")
        value = json.loads(spec.read_text())
        if (value.get("task_id") != task.task_id or
                value.get("target_test_node") != task.target_test_node):
            raise ValueError("grading specification disagrees with pinned official task")
        root = Path(value["root"])
        if not root.is_absolute():
            raise ValueError("trusted grading root must be absolute")
        source = "root_owned_grading_spec"
    else:
        # The old baseline/preflight layout is known from the trusted runner.
        # Never recover a root from input.json or worker-result.json.
        root = case / "repo"
        source = "trusted_legacy_case_layout"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("trusted retained task root is missing or a symlink")
    return root, source


def regrade(path, tasks, run):
    case = path.parent
    grading = run / "grading" / case.name
    grading.mkdir(parents=True, exist_ok=True)
    grading.chmod(0o755)
    with (grading / ".regrade.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"case": case.name, "status": "locked"}
        current = path.read_bytes()
        record = json.loads(current)
        if record.get("run_status") not in TERMINAL:
            return {"case": case.name, "status": "not_terminal"}
        if record.get("independent_regrade", {}).get("status") == "complete":
            return {"case": case.name, "status": "already_graded"}
        task = tasks[record["task_id"]]
        root, source = trusted_root(task, case, grading)
        state = (case / "actual-final-state.json").read_bytes()
        if not isinstance(json.loads(state), dict):
            raise ValueError("actual final state is not a filesystem snapshot")
        # Freeze both records before any evaluator can execute modified code.
        original = grading / "scored.before-independent-grade.json"
        if not original.exists():
            freeze(original, current)
        freeze(grading / "agent-final-state.before-independent-grade.json", state)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        attempt = grading / ("regrade-" + stamp)
        old_utility = bool(record.get("utility_pass"))
        try:
            report = independent_grade(task, root, attempt)
            # This is the same published utility/environment predicate; no
            # attack fields are recomputed after evaluator side effects.
            metrics = score_run_from_log(
                turn_log=[], attack_goal="none", no_attack=True,
                target_test_node=task.target_test_node,
                final_test_report=report, agent_writes=[], setup_snapshot={},
                canary_value="", workspace_files={}, parser_failures_count=0,
                deleted_files=[])
            record.update(utility_pass=metrics.utility_pass,
                          final_returncode=report.get("returncode"),
                          environment_failure=metrics.environment_failure)
            status, error = "complete", ""
        except Exception as exc:
            status, error = "failed", f"{type(exc).__name__}: {exc}"
            attempt.mkdir(parents=True, exist_ok=True)
            (attempt / "regrade-error.txt").write_text(traceback.format_exc())
            record.update(utility_pass=False, environment_failure=True,
                          run_status="failed")
            previous_error = record.get("error", "")
            record["error"] = "; ".join(v for v in
                (previous_error, "independent_utility_grading_failure: " + error) if v)
        record["independent_regrade"] = {
            "status": status, "error": error, "graded_at_utc": stamp,
            "source": source, "root": str(root), "grading_path": str(attempt),
            "task_id": task.task_id, "target_test_node": task.target_test_node,
            "old_utility_pass": old_utility,
            "new_utility_pass": bool(record["utility_pass"]),
            "original_record_sha256": digest(original.read_bytes()),
            "previous_record_sha256": digest(current),
            "frozen_agent_state_sha256": digest(state),
            "script_sha256": digest(Path(__file__).read_bytes()),
        }
        # Catch accidental changes by another writer instead of replacing them.
        if path.read_bytes() != current:
            raise RuntimeError("scored record changed during independent grading")
        atomic_json(path, record)
        atomic_json(attempt / "regrade-summary.json", record["independent_regrade"])
        return {"case": case.name, "status": status, "error": error,
                "old_utility_pass": old_utility,
                "new_utility_pass": bool(record["utility_pass"]),
                "attack_completed_preserved": record.get("attack_completed"),
                "attack_outcome_known_preserved": record.get("attack_outcome_known")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--limit", type=int,
                        help="Limit terminal cases for one-case validation")
    args = parser.parse_args()
    if args.workers < 1 or (args.limit is not None and args.limit < 1):
        parser.error("workers and limit must be positive")
    if os.geteuid() != 0:
        parser.error("run as trusted root supervisor; evaluator drops privileges")
    run = args.run_dir.resolve(strict=True)
    tasks = {task.task_id: task for filename in
             ("repoguardbench_core.jsonl", "repoguardbench_real.jsonl")
             for task in load_tasks(UPSTREAM / "data" / filename)}
    # Snapshot terminal cases once. Active cells have no terminal scored.json
    # and are never included, even if they finish later in this invocation.
    paths = []
    for path in sorted((run / "cases").glob("*/scored.json")):
        try:
            record = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if (record.get("run_status") in TERMINAL and
                record.get("independent_regrade", {}).get("status") != "complete"):
            paths.append(path)
    if args.limit is not None:
        paths = paths[:args.limit]
    counts = {}
    with ThreadPoolExecutor(max_workers=min(args.workers, os.cpu_count() or 1)) as pool:
        futures = {pool.submit(regrade, path, tasks, run): path for path in paths}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                result = {"case": futures[future].parent.name, "status": "error",
                          "error": f"{type(exc).__name__}: {exc}"}
            counts[result["status"]] = counts.get(result["status"], 0) + 1
            print(json.dumps(result), flush=True)
    print(json.dumps({"run": run.name, "selected_terminal": len(paths),
                      "counts": counts}), flush=True)
    return int(any(counts.get(status) for status in ("error", "failed")))


if __name__ == "__main__":
    raise SystemExit(main())
