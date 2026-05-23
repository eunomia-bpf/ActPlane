#!/usr/bin/env python3
"""Inject ActPlane corrective feedback into agent hook context.

The hook does not evaluate policy. ActPlane's eBPF/LSM enforcer writes
kernel-detected violations to ACTPLANE_FEEDBACK_FILE; this script only forwards
new feedback bytes to Codex/Claude as model-visible hook context.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


DEFAULT_MAX_CHARS = 8000


def load_hook_input() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def path_from_env_or_cwd(name: str, cwd: Path, default: str) -> Path:
    value = os.environ.get(name)
    path = Path(value) if value else cwd / default
    if not path.is_absolute():
        path = cwd / path
    return path


def load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_state(path: Path, feedback_path: Path, offset: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps({"feedback_file": str(feedback_path), "offset": offset}) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def new_feedback(feedback_path: Path, state_path: Path) -> str:
    try:
        size = feedback_path.stat().st_size
    except OSError:
        return ""

    state = load_state(state_path)
    previous_path = state.get("feedback_file")
    offset = state.get("offset", 0)
    if previous_path != str(feedback_path) or not isinstance(offset, int):
        offset = 0
    if offset < 0 or offset > size:
        offset = 0
    if offset == size:
        return ""

    with feedback_path.open("rb") as f:
        f.seek(offset)
        chunk = f.read(size - offset)
    save_state(state_path, feedback_path, size)
    return chunk.decode("utf-8", errors="replace").strip()


def context_text(feedback: str, max_chars: int) -> str:
    if len(feedback) > max_chars:
        feedback = "... truncated ...\n" + feedback[-max_chars:]
    return (
        "ActPlane detected an OS-level harness violation during the previous "
        "tool action. Treat this as authoritative feedback from the kernel "
        "enforcer; do not retry the same operation unchanged. Follow the "
        "suggested alternative or satisfy the listed precondition.\n\n"
        f"{feedback}"
    )


def hook_output(event: str, feedback: str, max_chars: int) -> dict[str, Any]:
    context = context_text(feedback, max_chars)
    return {
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": context,
        }
    }


def main() -> int:
    data = load_hook_input()
    cwd = Path(data.get("cwd") or os.getcwd()).resolve()
    event = str(data.get("hook_event_name") or "PostToolUse")
    feedback_path = path_from_env_or_cwd(
        "ACTPLANE_FEEDBACK_FILE", cwd, ".actplane/last-violation.txt"
    )
    state_override = os.environ.get("ACTPLANE_HOOK_STATE")
    if state_override:
        state_path = path_from_env_or_cwd(
            "ACTPLANE_HOOK_STATE", cwd, ".actplane/feedback-hook.state.json"
        )
    else:
        state_path = feedback_path.parent / "feedback-hook.state.json"
    try:
        max_chars = int(os.environ.get("ACTPLANE_HOOK_MAX_CHARS", DEFAULT_MAX_CHARS))
    except ValueError:
        max_chars = DEFAULT_MAX_CHARS

    feedback = new_feedback(feedback_path, state_path)
    if not feedback:
        return 0

    print(json.dumps(hook_output(event, feedback, max_chars), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
