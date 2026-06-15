#!/usr/bin/env python3
"""Internal local llama.cpp server manager for RQ1 eval.

Reported experiments must invoke this through run_eval.py, which starts one
server for the source agent and restarts it in JSON mode for trajectory judging.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

DEFAULT_LLAMA_SERVER = Path(
    os.environ.get("LLAMA_SERVER_BIN")
    or shutil.which("llama-server")
    or "llama-server"
)
DEFAULT_MODEL = Path(
    os.environ.get(
        "LLAMA_MODEL",
        os.path.expanduser(
            "~/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/"
            "snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/"
            "Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf"
        ),
    )
)
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18080
DEFAULT_DEVICE = "CUDA0"
DEFAULT_GPU_LAYERS = "all"
DEFAULT_CTX_SIZE = 192000


class LlamaServer:
    def __init__(
        self,
        server_bin: Path = DEFAULT_LLAMA_SERVER,
        model_path: Path = DEFAULT_MODEL,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        device: str = DEFAULT_DEVICE,
        gpu_layers: str = DEFAULT_GPU_LAYERS,
        ctx_size: int = DEFAULT_CTX_SIZE,
        judge_json: bool = False,
        log_path: Path | None = None,
        restart_existing: bool = False,
    ):
        self.server_bin = Path(server_bin)
        self.model_path = Path(model_path)
        self.host = host
        self.port = port
        self.device = device
        self.gpu_layers = gpu_layers
        self.ctx_size = ctx_size
        self.judge_json = judge_json
        self.log_path = Path(log_path) if log_path else None
        self.restart_existing = restart_existing
        self.base_url = f"http://{host}:{port}"
        self.proc: subprocess.Popen | None = None
        self._log_file = None

    def healthy(self) -> bool:
        try:
            with urlopen(f"{self.base_url}/health", timeout=2) as response:
                return response.status == 200
        except (OSError, URLError):
            return False

    def _existing_pids(self) -> list[int]:
        result = subprocess.run(
            ["pgrep", "-af", f"llama-server.*--port {self.port}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        pids: list[int] = []
        own_pid = os.getpid()
        for line in result.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if not parts:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            if pid != own_pid:
                pids.append(pid)
        return pids

    def stop_existing(self, grace_s: float = 20) -> None:
        pids = self._existing_pids()
        if not pids:
            return
        print(f"Stopping existing llama-server processes on port {self.port}: {pids}")
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.time() + grace_s
        while time.time() < deadline:
            live = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    live.append(pid)
                except ProcessLookupError:
                    pass
            if not live:
                return
            time.sleep(0.5)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(1)

    def command(self) -> list[str]:
        cmd = [
            str(self.server_bin),
            "-m",
            str(self.model_path),
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--device",
            self.device,
            "-ngl",
            self.gpu_layers,
            "-c",
            str(self.ctx_size),
            "--no-webui",
            "--reasoning",
            "off",
            "--reasoning-format",
            "none",
        ]
        if self.judge_json:
            cmd.extend(["--json-schema", "{}"])
        return cmd

    def start(self, timeout: float = 120) -> None:
        if self.restart_existing:
            self.stop_existing()
            if self.healthy():
                raise RuntimeError(
                    f"llama-server at {self.base_url} is still healthy after "
                    "restart_existing stop. Refusing to reuse an externally "
                    "managed server with unknown parameters."
                )

        if self.healthy():
            print(f"llama-server already running at {self.base_url}")
            return

        if not self.server_bin.exists():
            resolved = shutil.which(str(self.server_bin))
            if resolved:
                self.server_bin = Path(resolved)
        if not self.server_bin.exists():
            raise FileNotFoundError(
                f"llama-server not found: {self.server_bin}. "
                "Set LLAMA_SERVER_BIN or put llama-server on PATH."
            )
        if not self.model_path.exists():
            raise FileNotFoundError(f"model not found: {self.model_path}")

        cmd = self.command()
        print(
            "Starting llama-server with "
            f"n_ctx={self.ctx_size}, device={self.device}, "
            f"judge_json={self.judge_json}"
        )
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = self.log_path.open("w", encoding="utf-8")
            stdout = self._log_file
            stderr = subprocess.STDOUT
        env = os.environ.copy()
        env.setdefault("CUDA_VISIBLE_DEVICES", "0")
        self.proc = subprocess.Popen(
            cmd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            text=True,
            preexec_fn=os.setsid,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                log_hint = f" See {self.log_path}" if self.log_path else ""
                raise RuntimeError(
                    f"llama-server exited with code {self.proc.returncode}.{log_hint}"
                )
            if self.healthy():
                print(f"llama-server healthy at {self.base_url}")
                return
            time.sleep(1)
        raise TimeoutError(f"llama-server did not become healthy within {timeout}s")

    def stop(self) -> None:
        if not self.proc:
            return
        print("Stopping llama-server...")
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            self.proc = None
            if self._log_file:
                self._log_file.close()
                self._log_file = None
            return
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait(timeout=10)
        self.proc = None
        if self._log_file:
            self._log_file.close()
            self._log_file = None
        print("llama-server stopped.")

    def model_name(self) -> str:
        return self.model_path.stem


if __name__ == "__main__":
    raise SystemExit(
        "llama_server.py is an internal helper. "
        "Use docs/eval_scripts/run_eval.py as the only eval entrypoint."
    )
