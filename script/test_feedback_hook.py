#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "script" / "actplane-feedback-hook.py"


def run_hook(cwd: Path, event: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    payload = {
        "session_id": "test",
        "cwd": str(cwd),
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    }
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=str(cwd),
        env=env,
        check=False,
    )


class FeedbackHookTest(unittest.TestCase):
    def test_codex_post_tool_use_gets_new_feedback_once(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            feedback = cwd / ".actplane" / "last-violation.txt"
            feedback.parent.mkdir()
            feedback.write_text("[ActPlane] first violation\n", encoding="utf-8")
            env = os.environ.copy()
            env["ACTPLANE_FEEDBACK_FILE"] = str(feedback)

            first = run_hook(cwd, "PostToolUse", env)
            self.assertEqual(first.returncode, 0, first.stderr)
            data = json.loads(first.stdout)
            output = data["hookSpecificOutput"]
            self.assertEqual(output["hookEventName"], "PostToolUse")
            self.assertIn("first violation", output["additionalContext"])

            second = run_hook(cwd, "PostToolUse", env)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(second.stdout, "")

    def test_claude_post_tool_use_failure_receives_appended_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            feedback = cwd / ".actplane" / "last-violation.txt"
            feedback.parent.mkdir()
            feedback.write_text("[ActPlane] old violation\n", encoding="utf-8")
            env = os.environ.copy()
            env["ACTPLANE_FEEDBACK_FILE"] = str(feedback)

            first = run_hook(cwd, "PostToolUse", env)
            self.assertEqual(first.returncode, 0, first.stderr)

            with feedback.open("a", encoding="utf-8") as f:
                f.write("----\n[ActPlane] claude failure feedback\n")

            second = run_hook(cwd, "PostToolUseFailure", env)
            self.assertEqual(second.returncode, 0, second.stderr)
            data = json.loads(second.stdout)
            output = data["hookSpecificOutput"]
            self.assertEqual(output["hookEventName"], "PostToolUseFailure")
            self.assertNotIn("old violation", output["additionalContext"])
            self.assertIn("claude failure feedback", output["additionalContext"])

if __name__ == "__main__":
    unittest.main()
