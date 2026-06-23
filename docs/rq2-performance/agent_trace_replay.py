#!/usr/bin/env python3
"""Replay corpus-derived agent tool traces as a deterministic overhead workload."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]


def parse_csv(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def install_stubs(bin_dir: Path) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    write_executable(
        bin_dir / "git",
        """#!/usr/bin/env sh
printf '%s\n' "git $*" >> .agent-trace-git.log
exit 0
""",
    )
    write_executable(
        bin_dir / "uv",
        """#!/usr/bin/env sh
printf '%s\n' "uv $*" >> .agent-trace-tools.log
exit 0
""",
    )
    write_executable(
        bin_dir / "pytest",
        """#!/usr/bin/env sh
printf '%s\n' "pytest $*" >> .agent-trace-tools.log
printf '%s\n' "4 passed"
exit 0
""",
    )
    write_executable(
        bin_dir / "prek",
        """#!/usr/bin/env sh
printf '%s\n' "prek $*" >> .agent-trace-tools.log
exit 0
""",
    )


def safe_path(workspace: Path, raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return workspace / "absroot" / str(path).lstrip("/")
    parts = [p for p in path.parts if p not in {"", ".", ".."}]
    return workspace.joinpath(*parts) if parts else workspace / "empty"


def default_content(path: Path) -> str:
    suffix = path.suffix
    if suffix == ".py":
        return "def placeholder():\n    return 200\n"
    if suffix == ".ts":
        return "export const placeholder = 1;\n"
    if suffix == ".go":
        return "package main\n\nfunc main() {}\n"
    if suffix in {".md", ".txt"}:
        return "placeholder content\n"
    if suffix in {".yaml", ".yml"}:
        return "key: value\n"
    return "placeholder content\n"


def ensure_file(path: Path, content: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(content if content is not None else default_content(path), encoding="utf-8")


def seed_workspace(workspace: Path) -> None:
    dirs = [
        "src/lib/commands",
        "src/openagent",
        "src/utils",
        "skills/deployment/scripts",
        "server/handlers",
        "sdks/python/opensandbox",
        "tests",
        "config",
        "backups",
    ]
    for dirname in dirs:
        (workspace / dirname).mkdir(parents=True, exist_ok=True)
    files = {
        ".env": "PORT=3000\nREDIS_URL=redis://localhost:6379\n",
        ".gitignore": ".env\n",
        "README.md": "project README with automated reseaning and testing\n",
        "src/lib/commands/status.ts": "export function status() { return 'ok'; }\n",
        "src/lib/cli.ts": "export const cli = true;\n",
        "src/utils/helpers.ts": "export function helper() { return true; }\n",
        "src/utils/validators.ts": "export function valid() { return true; }\n",
        "src/openagent/chat.py": "class Response:\n    def __init__(self, status_code=200, body=''):\n        self.status_code = status_code\n        self.body = body\n",
        "tests/test_chat.py": "def test_placeholder():\n    assert True\n",
        "config/settings.yaml": "database:\n  host: localhost\n  port: 5432\n",
        "skills/deployment/SKILL.md": "# deployment skill\n",
        "skills/deployment/config.yaml": "setting: value\n",
        "server/handlers/sandbox.go": "package handlers\n",
        "sdks/python/opensandbox/client.py": "class Client:\n    pass\n",
        "src/config.py": "import os\nPAYMENT_API_KEY = os.getenv('PAYMENT_API_KEY', '')\n",
        "src/types.ts": "export type AuditEntry = { operation: 'create' | 'update' }\n",
        "src/audit.ts": "export function logAudit() { return true }\n",
    }
    for rel, content in files.items():
        ensure_file(workspace / rel, content)


def tool_uses(event: dict[str, Any]) -> list[dict[str, Any]]:
    uses: list[dict[str, Any]] = []
    content = event.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use":
                uses.append(item)
    return uses


def run_bash(command: str, workspace: Path, env: dict[str, str], timeout: int) -> None:
    proc = subprocess.run(
        ["bash", "-lc", command],
        cwd=workspace,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    (workspace / ".agent-trace-bash.log").open("a", encoding="utf-8").write(
        json.dumps(
            {
                "command": command,
                "returncode": proc.returncode,
                "stdout": proc.stdout[-2000:],
                "stderr": proc.stderr[-2000:],
            },
            sort_keys=True,
        )
        + "\n"
    )
    if proc.returncode != 0:
        raise RuntimeError(f"bash command failed ({proc.returncode}): {command}\n{proc.stderr}")


def replay_trace(trace: Path, workspace: Path, env: dict[str, str], timeout: int) -> dict[str, Any]:
    actions = 0
    bash_commands = 0
    reads = 0
    writes = 0
    edits = 0
    for line in trace.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        for use in tool_uses(event):
            name = str(use.get("name", ""))
            inp = use.get("input") if isinstance(use.get("input"), dict) else {}
            actions += 1
            if name == "Read":
                path = safe_path(workspace, str(inp.get("file_path", "missing.txt")))
                ensure_file(path)
                _ = path.read_text(encoding="utf-8", errors="replace")
                reads += 1
            elif name == "Write":
                path = safe_path(workspace, str(inp.get("file_path", "write.txt")))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(str(inp.get("content", "")), encoding="utf-8")
                writes += 1
            elif name == "Edit":
                path = safe_path(workspace, str(inp.get("file_path", "edit.txt")))
                old = str(inp.get("old_string", ""))
                new = str(inp.get("new_string", ""))
                ensure_file(path, old if old else None)
                text = path.read_text(encoding="utf-8", errors="replace")
                if old and old in text:
                    text = text.replace(old, new, 1)
                else:
                    text += "\n" + new + "\n"
                path.write_text(text, encoding="utf-8")
                edits += 1
            elif name == "Bash":
                run_bash(str(inp.get("command", "true")), workspace, env, timeout)
                bash_commands += 1
    return {
        "trace": str(trace),
        "actions": actions,
        "bash_commands": bash_commands,
        "reads": reads,
        "writes": writes,
        "edits": edits,
    }


def discover_traces(trace_root: Path, variants: list[str], limit: int) -> list[Path]:
    traces: list[Path] = []
    for variant in variants:
        traces.extend(sorted(trace_root.glob(f"*/*/trace_{variant}.jsonl")))
    traces = sorted(traces)
    return traces[:limit] if limit > 0 else traces


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-root", type=Path, default=ROOT / "docs/corpus-test")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--variants", default="compliant,violation")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--timeout-s", type=int, default=20)
    args = parser.parse_args()

    start = time.perf_counter()
    if args.workspace.exists():
        shutil.rmtree(args.workspace)
    args.workspace.mkdir(parents=True)
    bin_dir = (args.workspace / "bin").resolve()
    install_stubs(bin_dir)
    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")

    traces = discover_traces(args.trace_root, parse_csv(args.variants), args.limit)
    if not traces:
        raise SystemExit(f"no traces found under {args.trace_root}")

    per_trace = []
    totals = {"actions": 0, "bash_commands": 0, "reads": 0, "writes": 0, "edits": 0}
    for idx, trace in enumerate(traces, 1):
        rel = trace.relative_to(args.trace_root)
        trace_workspace = args.workspace / f"trace-{idx:03d}" / rel.parent
        trace_workspace.mkdir(parents=True, exist_ok=True)
        seed_workspace(trace_workspace)
        rec = replay_trace(trace, trace_workspace, env, args.timeout_s)
        per_trace.append(rec)
        for key in totals:
            totals[key] += int(rec[key])

    elapsed = time.perf_counter() - start
    print(
        json.dumps(
            {
                "benchmark": "agent_trace_replay",
                "trace_count": len(traces),
                "elapsed_s": elapsed,
                "workspace": str(args.workspace),
                **totals,
            },
            sort_keys=True,
        )
    )
    (args.workspace / "summary.json").write_text(
        json.dumps({"traces": per_trace, "totals": totals, "elapsed_s": elapsed}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
