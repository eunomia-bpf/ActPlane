#!/usr/bin/env python3
"""Generate the three RQ2 overhead figures."""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

import matplotlib.pyplot as plt


CONFIG_LABELS = {
    "baseline": "Native",
    "ap-1": "AP-1",
    "ap-10": "AP-10",
    "ap-32": "AP-32",
    "ap-100": "AP-100",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def median(values: list[float]) -> float:
    values = sorted(values)
    if not values:
        return 0.0
    mid = len(values) // 2
    if len(values) % 2:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2.0


def bootstrap_ci(values: list[float], samples: int = 5000) -> tuple[float, float]:
    if len(values) <= 1:
        value = values[0] if values else 0.0
        return value, value
    rng = random.Random(42)
    meds = []
    for _ in range(samples):
        draw = [values[rng.randrange(len(values))] for _ in values]
        meds.append(median(draw))
    meds.sort()
    return meds[int(0.025 * samples)], meds[int(0.975 * samples)]


def savefig(out_dir: Path, stem: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "pdf"):
        plt.savefig(out_dir / f"{stem}.{ext}", bbox_inches="tight", dpi=220)
    plt.close()


def plot_syscall_micro(micro_dir: Path, out_dir: Path) -> dict[str, object]:
    rows = read_csv(micro_dir / "aggregate.csv")
    by_key = {(r["config"], r["op"]): r for r in rows}
    ops = ["open", "write", "connect", "fork", "exec"]
    configs = ["ap-1", "ap-10", "ap-32", "ap-100"]
    xs = [1, 10, 32, 100]

    plt.figure(figsize=(7.2, 4.4))
    for op in ops:
        base = float(by_key[("baseline", op)]["median_p50_ns"])
        ys = []
        for cfg in configs:
            value = float(by_key[(cfg, op)]["median_p50_ns"])
            ys.append((value - base) / 1000.0)
        plt.plot(xs, ys, marker="o", linewidth=2, label=op)
    plt.axhline(0, color="#555555", linewidth=0.8)
    plt.xscale("log")
    plt.xticks(xs, [str(x) for x in xs])
    plt.xlabel("Active no-hit rules")
    plt.ylabel("median latency overhead over native (us)")
    plt.title("Syscall-level median overhead")
    plt.grid(axis="y", linestyle=":", linewidth=0.7)
    plt.legend(ncol=3, frameon=False)
    savefig(out_dir, "fig_rq2a_syscall_micro")

    summary = {}
    for op in ops:
        base = float(by_key[("baseline", op)]["median_p99_ns"])
        ap100 = float(by_key[("ap-100", op)]["median_p99_ns"])
        summary[op] = {
            "baseline_p99_us": base / 1000.0,
            "ap100_p99_us": ap100 / 1000.0,
            "ap100_overhead_us": (ap100 - base) / 1000.0,
            "ap100_overhead_pct": float(by_key[("ap-100", op)]["overhead_p99_ns_pct"]),
        }
    return summary


def workload_values(macro_dir: Path, workload: str) -> dict[str, list[float]]:
    rows = read_csv(macro_dir / "runs.csv")
    out: dict[str, list[float]] = {}
    for row in rows:
        if row["workload"] != workload:
            continue
        elapsed = float(row.get("elapsed_s") or row["measured_elapsed_s"])
        out.setdefault(row["config"], []).append(elapsed)
    return out


def plot_macro_workload(
    macro_dir: Path,
    out_dir: Path,
    workload: str,
    stem: str,
    title: str,
) -> dict[str, object]:
    values = workload_values(macro_dir, workload)
    configs = [cfg for cfg in ["baseline", "ap-32", "ap-100"] if cfg in values]
    if "baseline" not in values:
        raise SystemExit(f"missing baseline rows for {workload}")
    base = median(values["baseline"])
    medians = []
    err_low = []
    err_high = []
    summary = {}
    for cfg in configs:
        norm = [v / base for v in values[cfg]]
        med = median(norm)
        lo, hi = bootstrap_ci(norm)
        medians.append(med)
        err_low.append(max(0.0, med - lo))
        err_high.append(max(0.0, hi - med))
        summary[cfg] = {
            "median_elapsed_s": median(values[cfg]),
            "normalized": med,
            "overhead_pct": (med - 1.0) * 100.0,
            "repeats": len(values[cfg]),
            "ci95_low": lo,
            "ci95_high": hi,
        }

    plt.figure(figsize=(5.1, 3.8))
    xs = list(range(len(configs)))
    colors = ["#8a8f98", "#3b7ea1", "#c45a2c"][: len(configs)]
    plt.bar(xs, medians, color=colors, width=0.62)
    plt.errorbar(xs, medians, yerr=[err_low, err_high], fmt="none", ecolor="#222222", capsize=4)
    plt.axhline(1.0, color="#333333", linewidth=0.9)
    plt.xticks(xs, [CONFIG_LABELS.get(c, c) for c in configs])
    plt.ylabel("Normalized elapsed time")
    plt.title(title)
    plt.ylim(0, max(1.12, max(medians) + max(err_high or [0]) + 0.06))
    plt.grid(axis="y", linestyle=":", linewidth=0.7)
    savefig(out_dir, stem)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--micro-dir", type=Path, required=True)
    parser.add_argument("--macro-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("docs/rq2-performance/tmp/rq2-figures"))
    args = parser.parse_args()

    summary = {
        "micro": plot_syscall_micro(args.micro_dir, args.out_dir),
        "linux_build": plot_macro_workload(
            args.macro_dir,
            args.out_dir,
            "linux-build",
            "fig_rq2b_linux_build",
            "Linux build macro overhead",
        ),
        "agent_trace": plot_macro_workload(
            args.macro_dir,
            args.out_dir,
            "agent-trace",
            "fig_rq2c_agent_trace",
            "Agent trace replay overhead",
        ),
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(f"[plot] wrote {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
