#!/usr/bin/env python3
"""Run OctoBench cases under baseline, tool-regex, or ActPlane conditions.

The baseline condition calls upstream mini-vela's benchmark_runner.py directly.
The enforcement conditions keep upstream mini-vela unchanged, reuse its scaffold
builders, and change only where the case-specific policy is enforced.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
MINI_VELA = ROOT / "mini-vela"
EVAL_SCRIPTS = ROOT.parent / "eval_scripts"
DEFAULT_DATASET = ROOT / "data" / "selected_cases_21.jsonl"
DEFAULT_VENV = Path("/tmp/octobench-litellm-venv")
DEFAULT_ACTPLANE = ROOT.parents[1] / "target" / "release" / "actplane"
DEFAULT_POLICY_ROOT = ROOT / "policies"
DEFAULT_LITELLM_CONFIG = ROOT / "configs" / "litellm_llama_cpp.yaml"
TOOL_REGEX_HOOK = ROOT / "tool_regex_hook.py"
ACTPLANE_FEEDBACK_HOOK = ROOT / "actplane_feedback_hook.py"
INSTANCE_ID_FILE = Path("/tmp/current_instance_id.txt")
CONDITIONS = ("baseline", "tool-regex", "actplane", "actplane-feedback")
MANAGED_LLAMA_CTX = 192000
UPSTREAM_NO_TIMEOUT_COMPAT_S = 86400
FORBIDDEN_SHARED_POLICY_TOKENS = (
    "no-git-branch-or-worktree",
    "no-unrequested-dependency-install",
    "read-workspace-before-write",
    "WORKSPACE_CONTEXT",
    "git branch/worktree",
    "dependency manager install",
    "workspace write without prior workspace read",
)

sys.path.insert(0, str(EVAL_SCRIPTS))
sys.path.insert(0, str(MINI_VELA))

from llama_server import LlamaServer  # noqa: E402
from scaffolds import DEFAULT_MODEL, get_scaffold  # noqa: E402


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_cases(dataset: Path, limit: int | None, case_ids: list[str]) -> list[dict[str, Any]]:
    all_cases: list[dict[str, Any]] = []
    with dataset.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                all_cases.append(json.loads(line))

    if case_ids:
        by_id = {case["instance_id"]: case for case in all_cases}
        missing = [case_id for case_id in case_ids if case_id not in by_id]
        if missing:
            raise SystemExit(f"case not found in {dataset}: {', '.join(missing)}")
        selected = [by_id[case_id] for case_id in case_ids]
    else:
        selected = all_cases

    return selected[:limit] if limit is not None else selected


def wait_url(url: str, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status < 500:
                    return True
        except Exception:
            time.sleep(2)
    return False


def kill_process_tree(proc: subprocess.Popen, grace_s: int = 10) -> None:
    if proc.poll() is not None:
        return
    signal_group = False
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    if pgid != os.getpgrp():
        signal_group = True

    try:
        if signal_group:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
    except ProcessLookupError:
        return

    deadline = time.time() + grace_s
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.5)

    try:
        if signal_group:
            os.killpg(pgid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass
    proc.wait(timeout=10)


def stop_stale_proxy_processes(ports: tuple[int, ...] = (4000, 4001), grace_s: float = 5) -> None:
    own_pid = os.getpid()
    pids: list[int] = []
    port_tokens = {str(port) for port in ports}
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        pid = int(proc_dir.name)
        if pid == own_pid:
            continue
        try:
            raw = (proc_dir / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        parts = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
        if not parts:
            continue
        if "__proxy__" not in parts and "__proxy_raw__" not in parts:
            continue
        if not any(part.endswith("run_cases.py") for part in parts):
            continue
        if not any(token in port_tokens for token in parts):
            continue
        pids.append(pid)

    if not pids:
        return

    for pid in pids:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError:
            os.kill(pid, signal.SIGTERM)

    deadline = time.time() + grace_s
    while time.time() < deadline:
        live: list[int] = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                live.append(pid)
            except ProcessLookupError:
                pass
        if not live:
            return
        time.sleep(0.25)

    for pid in pids:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def stop_process_tree_with_signal(proc: subprocess.Popen, sig: int, grace_s: int = 10) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        return

    deadline = time.time() + grace_s
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.5)
    kill_process_tree(proc, grace_s=2)


def feedback_rule_id(record: str) -> str:
    match = re.search(r'\{"actplane_rule":"([^"]+)"', record)
    if match:
        return match.group(1)
    reason_match = re.search(r"(?:- Reason:|reason:)\s*([^\n]+)", record)
    if reason_match:
        return reason_match.group(1).strip()
    return record[:80]


def summarize_feedback_record(record: str) -> str:
    rule = feedback_rule_id(record)
    reason_match = re.search(r"(?:- Reason:|reason:)\s*([^\n]+)", record)
    op_match = re.search(r"\[ActPlane\] Operation `([^`]+)`", record)
    if not op_match:
        op_match = re.search(r"VIOLATION: process '[^']+' \([^)]*\) — ([^\n]+)", record)
    parts = [f"- rule={rule}"]
    if op_match:
        parts.append(f"observed={op_match.group(1)}")
    if reason_match:
        parts.append(f"reason={reason_match.group(1).strip()}")
    parts.append("next_step=do not repeat that OS operation unchanged")
    return "; ".join(parts)


class FeedbackBodyInjector:
    def __init__(self, feedback_file: Path, trajectory_dir: Path) -> None:
        self.feedback_file = feedback_file
        self.trajectory_dir = trajectory_dir
        self.offset = 0
        self.lock = threading.Lock()

    def _read_new_feedback(self) -> str:
        try:
            size = self.feedback_file.stat().st_size
        except FileNotFoundError:
            self.offset = 0
            return ""
        if self.offset > size:
            self.offset = 0
        if self.offset == size:
            return ""
        with self.feedback_file.open("rb") as f:
            f.seek(self.offset)
            raw = f.read()
        self.offset = size
        return raw.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _compact_feedback(text: str) -> str:
        selected: list[str] = []
        seen_rules: set[str] = set()
        if "🚫 VIOLATION:" in text:
            records = [
                "🚫 VIOLATION:" + part.strip()
                for part in text.split("🚫 VIOLATION:")[1:]
                if part.strip()
            ]
        elif "TAINT_VIOLATION" not in text and '"actplane_rule"' not in text:
            return ""
        else:
            records = [part.strip() for part in text.split("\n----") if part.strip()]
        for record in records:
            rule = feedback_rule_id(record)
            if rule in seen_rules:
                continue
            seen_rules.add(rule)
            selected.append(summarize_feedback_record(record))
            if len(selected) >= 3:
                break
        compact = "\n".join(selected)
        if len(compact) > 2000:
            compact = compact[-2000:]
        return compact

    @staticmethod
    def _append_content_text(content: Any, feedback: str) -> Any:
        if isinstance(content, str):
            return content + "\n\n" + feedback
        if isinstance(content, list):
            content.append({"type": "text", "text": feedback})
            return content
        return feedback

    @staticmethod
    def _inject_anthropic_system(payload: dict[str, Any], feedback: str) -> None:
        system = payload.get("system")
        if isinstance(system, str):
            payload["system"] = system + "\n\n" + feedback
        elif isinstance(system, list):
            system.append({"type": "text", "text": feedback})
        else:
            payload["system"] = [{"type": "text", "text": feedback}]

    def _inject_chat_system(self, payload: dict[str, Any], feedback: str) -> None:
        messages = payload.get("messages")
        if not isinstance(messages, list):
            payload["messages"] = [{"role": "system", "content": feedback}]
            return
        for message in messages:
            if isinstance(message, dict) and message.get("role") == "system":
                message["content"] = self._append_content_text(message.get("content"), feedback)
                return
        messages.insert(0, {"role": "system", "content": feedback})

    def inject(self, path: str, body: bytes) -> bytes:
        parsed = urllib.parse.urlsplit(path)
        endpoint = parsed.path.rstrip("/")
        if endpoint not in {"/v1/messages", "/v1/chat/completions", "/chat/completions"}:
            return body
        with self.lock:
            text = self._read_new_feedback()
        if not text:
            return body
        if (
            "🚫 VIOLATION:" not in text
            and "TAINT_VIOLATION" not in text
            and '"actplane_rule"' not in text
        ):
            return body
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return body
        feedback = (
            "ActPlane detected OS-level policy feedback during the previous "
            "tool action. Treat it as authoritative kernel feedback. Do not "
            "retry the same operation unchanged; adjust the next step according "
            "to the reason below.\n\n"
            f"{text}"
        )
        if endpoint == "/v1/messages":
            self._inject_anthropic_system(payload, feedback)
        else:
            self._inject_chat_system(payload, feedback)
        print(f"[ActPlaneFeedbackProxy] injected feedback into {endpoint}", flush=True)
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def _current_instance_id(self) -> str:
        try:
            return INSTANCE_ID_FILE.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return "unknown"

    def _write_trajectory_record(self, feedback: str) -> None:
        instance_id = self._current_instance_id()
        if not instance_id:
            instance_id = "unknown"
        self.trajectory_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "session_id": instance_id,
            "biz_id": "",
            "request_time": int(time.time() * 1000),
            "request_body": {
                "messages": [],
                "system": [{"type": "text", "text": feedback}],
                "tools": [],
                "model": "actplane-feedback-proxy",
                "max_tokens": 0,
                "metadata": {"actplane_feedback_injected": True},
            },
            "response_body": {"content": []},
        }
        output_file = self.trajectory_dir / f"{instance_id}.jsonl"
        with output_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_raw_proxy_main(config_path: Path, port: int) -> None:
    proxy_dir = MINI_VELA / "proxy"
    sys.path.insert(0, str(proxy_dir))
    os.chdir(proxy_dir)

    import litellm  # noqa: PLC0415
    from trajectory_logger import trajectory_logger_instance  # noqa: PLC0415

    litellm.callbacks.append(trajectory_logger_instance)

    print("=" * 60)
    print("[run_cases proxy] registered upstream TrajectoryLogger callback")
    print(f"[run_cases proxy] trajectory dir: {trajectory_logger_instance.output_dir}")
    print(f"[run_cases proxy] config: {config_path}")
    print(f"[run_cases proxy] port: {port}")
    print("=" * 60)

    sys.argv = [
        "litellm",
        "--config",
        str(config_path),
        "--port",
        str(port),
    ]

    from litellm.proxy.proxy_cli import run_server  # noqa: PLC0415

    run_server()


def run_feedback_proxy_main(config_path: Path, port: int) -> None:
    internal_port = port + 1
    env = os.environ.copy()
    env.pop("OCTOBENCH_ACTPLANE_FEEDBACK_INJECT", None)
    internal = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "run_cases.py"),
            "__proxy_raw__",
            str(config_path),
            str(internal_port),
        ],
        cwd=ROOT,
        env=env,
        text=True,
    )
    try:
        if not wait_url(f"http://127.0.0.1:{internal_port}/health/liveliness", timeout_s=120):
            raise RuntimeError("internal LiteLLM proxy did not become live")

        injector = FeedbackBodyInjector(
            Path(os.environ["OCTOBENCH_ACTPLANE_FEEDBACK_FILE"]),
            MINI_VELA / "results" / "trajectories",
        )
        upstream = f"http://127.0.0.1:{internal_port}"

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                print("[ActPlaneFeedbackProxy] " + fmt % args, flush=True)

            def do_GET(self) -> None:
                self._forward()

            def do_POST(self) -> None:
                self._forward()

            def do_OPTIONS(self) -> None:
                self._forward()

            def _forward(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length) if length else b""
                if self.command in {"POST", "PUT", "PATCH"} and body:
                    body = injector.inject(self.path, body)
                headers = {
                    key: value
                    for key, value in self.headers.items()
                    if key.lower() not in {"host", "content-length", "connection"}
                }
                data = body if self.command in {"POST", "PUT", "PATCH"} else None
                req = urllib.request.Request(
                    upstream + self.path,
                    data=data,
                    headers=headers,
                    method=self.command,
                )
                if data is not None:
                    req.add_header("Content-Length", str(len(data)))
                try:
                    with urllib.request.urlopen(req, timeout=600) as response:
                        response_body = response.read()
                        self.send_response(response.status)
                        for key, value in response.headers.items():
                            if key.lower() not in {"connection", "content-length", "transfer-encoding"}:
                                self.send_header(key, value)
                        self.send_header("Content-Length", str(len(response_body)))
                        self.end_headers()
                        self.wfile.write(response_body)
                except urllib.error.HTTPError as exc:
                    response_body = exc.read()
                    self.send_response(exc.code)
                    for key, value in exc.headers.items():
                        if key.lower() not in {"connection", "content-length", "transfer-encoding"}:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body)

        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        print(
            f"[ActPlaneFeedbackProxy] listening on {port}, forwarding to {internal_port}",
            flush=True,
        )
        server.serve_forever()
    finally:
        kill_process_tree(internal)


def run_proxy_main(config_path: Path, port: int) -> None:
    if os.environ.get("OCTOBENCH_ACTPLANE_FEEDBACK_INJECT") == "1":
        run_feedback_proxy_main(config_path, port)
    else:
        run_raw_proxy_main(config_path, port)


def start_proxy(
    venv: Path,
    log_path: Path,
    config_path: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen:
    stop_stale_proxy_processes()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("w", encoding="utf-8")
    env = os.environ.copy()
    env["PATH"] = f"{venv / 'bin'}:{env.get('PATH', '')}"
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(
        [str(venv / "bin" / "python"), str(ROOT / "run_cases.py"), "__proxy__", str(config_path), "4000"],
        cwd=ROOT,
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid,
    )
    if not wait_url("http://127.0.0.1:4000/health/liveliness", timeout_s=120):
        kill_process_tree(proc)
        raise RuntimeError(f"proxy did not become live; see {log_path}")
    return proc


def start_actplane_watch(actplane: Path, policy_path: Path, log_path: Path) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(actplane), "--policy", str(policy_path), "watch"],
        cwd=ROOT.parents[1],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid,
    )

    deadline = time.time() + 120
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"ActPlane watch exited early; see {log_path}")
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            text = ""
        if "ActPlane: watching with feedback file" in text:
            return proc
        time.sleep(0.5)
    stop_process_tree_with_signal(proc, signal.SIGINT)
    raise RuntimeError(f"ActPlane watch did not become ready; see {log_path}")


def reset_mini_vela_results(instance_id: str) -> Path:
    mini_results = MINI_VELA / "results"
    run_results = mini_results / "run_results.json"
    if run_results.exists():
        run_results.unlink()

    trajectory = mini_results / "trajectories" / f"{instance_id}.jsonl"
    if trajectory.exists():
        trajectory.unlink()

    (mini_results / "trajectories").mkdir(parents=True, exist_ok=True)
    return mini_results


def archive_mini_vela_results(mini_results: Path, case_dir: Path, instance_id: str) -> list[str]:
    if not mini_results.exists():
        return []

    archive = case_dir / "mini-vela-results"
    if archive.exists():
        shutil.rmtree(archive)
    (archive / "trajectories").mkdir(parents=True, exist_ok=True)

    run_results = mini_results / "run_results.json"
    if run_results.exists():
        shutil.copy2(run_results, archive / "run_results.json")

    trajectory = mini_results / "trajectories" / f"{instance_id}.jsonl"
    if trajectory.exists():
        shutil.copy2(trajectory, archive / "trajectories" / trajectory.name)

    return sorted(str(path) for path in (archive / "trajectories").glob(f"{instance_id}.jsonl"))


def parse_official_case_result(instance_id: str) -> dict[str, Any] | None:
    result_path = MINI_VELA / "results" / "run_results.json"
    if not result_path.exists():
        return None
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, list):
        return None
    for item in payload:
        if isinstance(item, dict) and item.get("instance_id") == instance_id:
            return item
    return None


def case_policy_path(policy_root: Path, condition: str, instance_id: str) -> Path:
    if condition == "tool-regex":
        return policy_root / "tool-regex" / f"{instance_id}.json"
    if condition in {"actplane", "actplane-feedback"}:
        return policy_root / condition / f"{instance_id}.yaml"
    raise ValueError(f"condition has no policy file: {condition}")


def validate_case_policy(policy_path: Path, condition: str, instance_id: str) -> None:
    if policy_path.stem != instance_id:
        raise SystemExit(
            f"policy filename does not match case {instance_id}: {policy_path}"
        )

    text = policy_path.read_text(encoding="utf-8")
    forbidden = [token for token in FORBIDDEN_SHARED_POLICY_TOKENS if token in text]
    if forbidden:
        raise SystemExit(
            f"shared guardrail token(s) in {policy_path}: {', '.join(forbidden)}"
        )

    if condition == "tool-regex":
        policy = json.loads(text)
        if policy.get("case_id") != instance_id:
            raise SystemExit(
                f"tool-regex policy case_id mismatch for {instance_id}: {policy_path}"
            )


def merge_claude_settings_script(update: dict[str, Any]) -> str:
    payload = json.dumps(update, ensure_ascii=False)
    code = (
        "import json,pathlib;"
        "p=pathlib.Path.home()/'.claude'/'settings.json';"
        "p.parent.mkdir(parents=True,exist_ok=True);"
        "text=p.read_text(encoding='utf-8') if p.exists() else '{}';"
        "data=json.loads(text or '{}');"
        f"update=json.loads({payload!r});"
        "hooks=data.setdefault('hooks',{});"
        "hooks.update(update.get('hooks',{}));"
        "p.write_text(json.dumps(data,ensure_ascii=False),encoding='utf-8')"
    )
    return "python3 -c " + shlex.quote(code)


def tool_regex_hook_setup_script() -> str:
    hook_settings = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": (
                                "python3 /tmp/tool_regex_hook.py "
                                "--policy /tmp/tool-regex-policy.json "
                                "--events /tmp/tool-regex-events.jsonl"
                            ),
                        }
                    ],
                }
            ],
        }
    }
    return merge_claude_settings_script(hook_settings)


def actplane_feedback_hook_setup_script() -> str:
    hook_targets = ["Bash", "Edit", "Write", "MultiEdit"]
    hooks = [
        {
            "matcher": target,
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 /tmp/actplane_feedback_hook.py",
                }
            ],
        }
        for target in hook_targets
    ]
    hook_settings = {
        "hooks": {
            "PostToolUse": hooks,
        }
    }
    return merge_claude_settings_script(hook_settings)


def force_claude_settings(
    commands: list[str],
    scaffold_name: str,
    extra_options: list[str] | None = None,
) -> list[str]:
    if scaffold_name != "claudecode":
        return commands
    option_text = ""
    if extra_options:
        option_text = " " + " ".join(extra_options)
    return [
        command.replace("claude ", f"claude --settings ~/.claude/settings.json{option_text} ", 1)
        if command.startswith("claude ")
        else command
        for command in commands
    ]


def load_tool_regex_disallowed_tools(policy_path: Path) -> list[str]:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    tools = policy.get("disallowed_tools", [])
    if not isinstance(tools, list):
        return []
    return [str(tool) for tool in tools if str(tool).strip()]


def build_plain_container_command(
    case: dict[str, Any],
    proxy_url: str,
    model: str,
) -> tuple[str, list[str], dict[str, str]]:
    scaffold_name = case.get("scaffold", {}).get("name", "claudecode")
    scaffold = get_scaffold(scaffold_name)
    setup_script = scaffold.get_setup_script(proxy_url, model=model)
    task_commands = scaffold.build_commands(
        case["user_query"],
        case.get("system_prompt", ""),
        model=model,
    )

    commands = [setup_script] + task_commands
    return " && ".join(commands), task_commands, scaffold.get_docker_env(proxy_url, model=model)


def build_tool_regex_container_command(
    case: dict[str, Any],
    proxy_url: str,
    model: str,
    policy_path: Path,
) -> tuple[str, list[str], dict[str, str]]:
    scaffold_name = case.get("scaffold", {}).get("name", "claudecode")
    scaffold = get_scaffold(scaffold_name)
    setup_script = scaffold.get_setup_script(proxy_url, model=model)
    task_commands = scaffold.build_commands(
        case["user_query"],
        case.get("system_prompt", ""),
        model=model,
    )

    commands = [setup_script]
    if scaffold_name == "claudecode":
        commands.append(tool_regex_hook_setup_script())
        disallowed_tools = load_tool_regex_disallowed_tools(policy_path)
        extra_options = []
        if disallowed_tools:
            extra_options = ["--disallowedTools", shlex.quote(",".join(disallowed_tools))]
        task_commands = force_claude_settings(
            task_commands,
            scaffold_name,
            extra_options=extra_options,
        )
    commands.extend(task_commands)
    return " && ".join(commands), task_commands, scaffold.get_docker_env(proxy_url, model=model)


def build_actplane_feedback_container_command(
    case: dict[str, Any],
    proxy_url: str,
    model: str,
) -> tuple[str, list[str], dict[str, str]]:
    scaffold_name = case.get("scaffold", {}).get("name", "claudecode")
    scaffold = get_scaffold(scaffold_name)
    setup_script = scaffold.get_setup_script(proxy_url, model=model)
    task_commands = scaffold.build_commands(
        case["user_query"],
        case.get("system_prompt", ""),
        model=model,
    )

    commands = [setup_script]
    commands.extend(task_commands)

    env_vars = scaffold.get_docker_env(proxy_url, model=model)
    return " && ".join(commands), task_commands, env_vars


def run_baseline_case(
    case: dict[str, Any],
    args: argparse.Namespace,
    case_dir: Path,
) -> dict[str, Any]:
    instance_id = case["instance_id"]
    upstream_timeout = (
        UPSTREAM_NO_TIMEOUT_COMPAT_S if args.timeout == 0 else args.timeout
    )
    cmd = [
        str(args.venv / "bin" / "python"),
        "benchmark_runner.py",
        "--dataset",
        str(args.dataset),
        "--model",
        args.model,
        "--case",
        instance_id,
        "--timeout",
        str(upstream_timeout),
        "--skip-proxy-check",
    ]
    write_json(
        case_dir / "command.json",
        {
            "cmd": cmd,
            "cwd": str(MINI_VELA),
            "requested_timeout_s": args.timeout,
            "upstream_timeout_s": upstream_timeout,
            "upstream_timeout_compat": args.timeout == 0,
        },
    )

    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=MINI_VELA,
        env={**os.environ, "PATH": f"{args.venv / 'bin'}:{os.environ.get('PATH', '')}"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    (case_dir / "stdout.txt").write_text(proc.stdout or "", encoding="utf-8")
    (case_dir / "stderr.txt").write_text(proc.stderr or "", encoding="utf-8")
    official_result = parse_official_case_result(instance_id)
    official_success = official_result.get("success") if official_result else None
    return {
        "instance_id": instance_id,
        "condition": args.condition,
        "returncode": proc.returncode,
        "process_success": proc.returncode == 0,
        "official_success": official_success,
        "official_result": official_result,
        "success": proc.returncode == 0 and official_success is True,
        "elapsed_s": time.time() - started,
    }


def run_actplane_case(
    case: dict[str, Any],
    args: argparse.Namespace,
    case_dir: Path,
) -> dict[str, Any]:
    instance_id = case["instance_id"]
    scaffold_name = case.get("scaffold", {}).get("name", "claudecode")
    proxy_url = "http://host.docker.internal:4000"
    policy_path = case_policy_path(args.policy_root, args.condition, instance_id)
    INSTANCE_ID_FILE.write_text(instance_id, encoding="utf-8")

    if args.condition == "actplane-feedback":
        full_command, task_commands, env_vars = build_actplane_feedback_container_command(
            case=case,
            proxy_url=proxy_url,
            model=args.model,
        )
    else:
        full_command, task_commands, env_vars = build_plain_container_command(
            case=case,
            proxy_url=proxy_url,
            model=args.model,
    )

    container_name = f"octobench-{args.condition}-{instance_id[:36]}-{int(time.time())}"
    feedback_dir = ROOT.parents[1] / ".actplane"
    feedback_dir.mkdir(parents=True, exist_ok=True)
    feedback_file = feedback_dir / "last-violation.txt"
    if feedback_file.exists():
        feedback_file.unlink()
    hook_state = feedback_dir / "hook.state.json"
    if hook_state.exists():
        hook_state.unlink()
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--add-host=host.docker.internal:host-gateway",
    ]
    for key, value in env_vars.items():
        docker_cmd.extend(["-e", f"{key}={value}"])
    docker_cmd.extend(
        [
            "-w",
            case.get("workspace_abs_path", "/app"),
            case["image"],
            "bash",
            "-c",
            full_command,
        ]
    )

    write_json(
        case_dir / "command.json",
        {
            "condition": args.condition,
            "container_name": container_name,
            "scaffold": scaffold_name,
            "model": args.model,
            "image": case["image"],
            "workspace_abs_path": case.get("workspace_abs_path"),
            "proxy_url": proxy_url,
            "policy": str(policy_path),
            "actplane": str(args.actplane),
            "actplane_mode": "host-watch",
            "feedback_hook": str(ACTPLANE_FEEDBACK_HOOK)
            if args.condition == "actplane-feedback"
            else None,
            "task_commands": task_commands,
            "docker_command": docker_cmd,
            "trajectory_session_id": instance_id,
        },
    )

    started = time.time()
    watch = start_actplane_watch(args.actplane, policy_path, case_dir / "actplane-watch.log")
    try:
        proc = subprocess.run(
            docker_cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=None if args.timeout == 0 else args.timeout,
        )
        result = {
            "instance_id": instance_id,
            "condition": args.condition,
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
            "timeout": False,
            "elapsed_s": time.time() - started,
        }
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = {
            "instance_id": instance_id,
            "condition": args.condition,
            "returncode": None,
            "success": False,
            "timeout": True,
            "timeout_s": args.timeout,
            "elapsed_s": time.time() - started,
        }
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
    finally:
        stop_process_tree_with_signal(watch, signal.SIGINT)

    (case_dir / "stdout.txt").write_text(stdout or "", encoding="utf-8")
    (case_dir / "stderr.txt").write_text(stderr or "", encoding="utf-8")
    return result


def run_tool_regex_case(
    case: dict[str, Any],
    args: argparse.Namespace,
    case_dir: Path,
) -> dict[str, Any]:
    instance_id = case["instance_id"]
    scaffold_name = case.get("scaffold", {}).get("name", "claudecode")
    proxy_url = "http://host.docker.internal:4000"
    policy_path = case_policy_path(args.policy_root, "tool-regex", instance_id)
    events_file = case_dir / "tool_regex_events.jsonl"
    events_file.touch()
    INSTANCE_ID_FILE.write_text(instance_id, encoding="utf-8")

    full_command, task_commands, env_vars = build_tool_regex_container_command(
        case=case,
        proxy_url=proxy_url,
        model=args.model,
        policy_path=policy_path,
    )

    container_name = f"octobench-tool-regex-{instance_id[:36]}-{int(time.time())}"
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--add-host=host.docker.internal:host-gateway",
        "-v",
        f"{TOOL_REGEX_HOOK}:/tmp/tool_regex_hook.py:ro",
        "-v",
        f"{policy_path}:/tmp/tool-regex-policy.json:ro",
        "-v",
        f"{events_file}:/tmp/tool-regex-events.jsonl",
    ]
    for key, value in env_vars.items():
        docker_cmd.extend(["-e", f"{key}={value}"])
    docker_cmd.extend(
        [
            "-w",
            case.get("workspace_abs_path", "/app"),
            case["image"],
            "bash",
            "-c",
            full_command,
        ]
    )

    write_json(
        case_dir / "command.json",
        {
            "condition": args.condition,
            "container_name": container_name,
            "scaffold": scaffold_name,
            "model": args.model,
            "image": case["image"],
            "workspace_abs_path": case.get("workspace_abs_path"),
            "proxy_url": proxy_url,
            "policy": str(policy_path),
            "hook": str(TOOL_REGEX_HOOK),
            "events_file": str(events_file),
            "cli_disallowed_tools": load_tool_regex_disallowed_tools(policy_path),
            "task_commands": task_commands,
            "docker_command": docker_cmd,
            "trajectory_session_id": instance_id,
        },
    )

    started = time.time()
    try:
        proc = subprocess.run(
            docker_cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=None if args.timeout == 0 else args.timeout,
        )
        result = {
            "instance_id": instance_id,
            "condition": args.condition,
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
            "timeout": False,
            "elapsed_s": time.time() - started,
        }
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = {
            "instance_id": instance_id,
            "condition": args.condition,
            "returncode": None,
            "success": False,
            "timeout": True,
            "timeout_s": args.timeout,
            "elapsed_s": time.time() - started,
        }
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""

    (case_dir / "stdout.txt").write_text(stdout or "", encoding="utf-8")
    (case_dir / "stderr.txt").write_text(stderr or "", encoding="utf-8")
    return result


def run_case(case: dict[str, Any], index: int, args: argparse.Namespace, run_dir: Path) -> dict[str, Any]:
    instance_id = case["instance_id"]
    case_dir = run_dir / f"{index:02d}-{instance_id}"
    case_dir.mkdir(parents=True, exist_ok=True)
    write_json(case_dir / "case.json", case)

    mini_results = reset_mini_vela_results(instance_id)
    proxy_env = None
    if args.condition == "actplane-feedback":
        feedback_dir = ROOT.parents[1] / ".actplane"
        feedback_dir.mkdir(parents=True, exist_ok=True)
        proxy_env = {
            "OCTOBENCH_ACTPLANE_FEEDBACK_INJECT": "1",
            "OCTOBENCH_ACTPLANE_FEEDBACK_FILE": str(case_dir / "actplane-watch.log"),
        }
    proxy = start_proxy(args.venv, case_dir / "proxy.log", args.litellm_config, proxy_env)
    try:
        if args.condition == "baseline":
            result = run_baseline_case(case, args, case_dir)
        elif args.condition == "tool-regex":
            result = run_tool_regex_case(case, args, case_dir)
        else:
            result = run_actplane_case(case, args, case_dir)
    finally:
        kill_process_tree(proxy)

    trajectories = archive_mini_vela_results(mini_results, case_dir, instance_id)
    result["trajectory_files"] = trajectories
    result["trajectory_count"] = len(trajectories)
    result["scorable"] = len(trajectories) == 1
    if not result["scorable"]:
        result["success"] = False
    write_json(case_dir / "result.json", result)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--condition", choices=CONDITIONS, required=True)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--case", action="append", default=[], help="Run only this instance_id. Can be repeated.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--venv", type=Path, default=DEFAULT_VENV)
    parser.add_argument("--policy-root", type=Path, default=DEFAULT_POLICY_ROOT)
    parser.add_argument("--actplane", type=Path, default=DEFAULT_ACTPLANE)
    parser.add_argument("--litellm-config", type=Path, default=DEFAULT_LITELLM_CONFIG)
    parser.add_argument("--managed-llama", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "results")
    return parser.parse_args()


def normalize_and_validate_args(args: argparse.Namespace) -> None:
    args.dataset = args.dataset.resolve()
    args.venv = args.venv.resolve()
    args.policy_root = args.policy_root.resolve()
    args.actplane = args.actplane.resolve()
    args.litellm_config = args.litellm_config.resolve()
    args.out_dir = args.out_dir.resolve()

    if not args.dataset.exists():
        raise SystemExit(f"dataset not found: {args.dataset}")
    if not (args.venv / "bin" / "python").exists():
        raise SystemExit(f"venv python not found: {args.venv / 'bin' / 'python'}")
    if not args.litellm_config.exists():
        raise SystemExit(f"LiteLLM config not found: {args.litellm_config}")
    if args.condition in {"tool-regex", "actplane", "actplane-feedback"} and not args.policy_root.exists():
        raise SystemExit(f"policy root not found: {args.policy_root}")
    if args.condition == "tool-regex" and not TOOL_REGEX_HOOK.exists():
        raise SystemExit(f"tool-regex hook not found: {TOOL_REGEX_HOOK}")
    if args.condition == "actplane-feedback" and not ACTPLANE_FEEDBACK_HOOK.exists():
        raise SystemExit(f"ActPlane feedback hook not found: {ACTPLANE_FEEDBACK_HOOK}")
    if args.condition in {"actplane", "actplane-feedback"}:
        if not args.actplane.exists():
            raise SystemExit(f"actplane binary not found: {args.actplane}")


def main() -> int:
    args = parse_args()
    normalize_and_validate_args(args)
    cases = load_cases(args.dataset, args.limit, args.case)
    for case in cases:
        if args.condition in {"tool-regex", "actplane", "actplane-feedback"}:
            policy_path = case_policy_path(args.policy_root, args.condition, case["instance_id"])
            if not policy_path.exists():
                raise SystemExit(f"policy not found for {case['instance_id']}: {policy_path}")
            validate_case_policy(policy_path, args.condition, case["instance_id"])

    run_dir = args.out_dir / args.condition / f"{args.condition}-isolated-{utc_stamp()}"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        run_dir / "metadata.json",
        {
            "condition": args.condition,
            "dataset": str(args.dataset),
            "case_ids": args.case,
            "limit": args.limit,
            "timeout_s": args.timeout,
            "model": args.model,
            "venv": str(args.venv),
            "policy_root": str(args.policy_root) if args.condition != "baseline" else None,
            "actplane": str(args.actplane)
            if args.condition in {"actplane", "actplane-feedback"}
            else None,
            "litellm_config": str(args.litellm_config),
            "managed_llama": args.managed_llama,
            "n_ctx": MANAGED_LLAMA_CTX,
            "case_parallel": 1,
            "case_count": len(cases),
        },
    )

    server = None
    if args.managed_llama:
        server = LlamaServer(
            judge_json=False,
            ctx_size=MANAGED_LLAMA_CTX,
            restart_existing=True,
            log_path=run_dir / "llama-server.log",
        )

    results: list[dict[str, Any]] = []
    try:
        if server:
            server.start(timeout=360)
        for index, case in enumerate(cases):
            print(f"[{index + 1}/{len(cases)}] {args.condition} {case['instance_id']}", flush=True)
            result = run_case(case, index, args, run_dir)
            results.append(result)
            write_json(run_dir / "summary.json", {"results": results})
            print(json.dumps(result, ensure_ascii=False), flush=True)
    finally:
        if server:
            server.stop()

    print(json.dumps({"run_dir": str(run_dir), "case_count": len(results)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "__proxy_raw__":
        if len(sys.argv) != 4:
            raise SystemExit("usage: run_cases.py __proxy_raw__ <litellm-config> <port>")
        run_raw_proxy_main(Path(sys.argv[2]).resolve(), int(sys.argv[3]))
        raise SystemExit(0)
    if len(sys.argv) >= 2 and sys.argv[1] == "__proxy__":
        if len(sys.argv) != 4:
            raise SystemExit("usage: run_cases.py __proxy__ <litellm-config> <port>")
        run_proxy_main(Path(sys.argv[2]).resolve(), int(sys.argv[3]))
        raise SystemExit(0)
    raise SystemExit(main())
